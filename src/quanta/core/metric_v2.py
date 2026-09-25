"""The Cryptographic Agility Score, metric-v2 (Master Plan section 8).

``S = 100 * (0.30 f_sites + 0.30 f_isolation + 0.20 f_config + 0.20 f_propagation)``

The weights are the pre-registered ``weights-v1`` and are never tuned. What changed from
v1 are the definitions, each to fix a defect found by testing the metric itself:

* ``f_isolation`` is the Herfindahl concentration of touchpoints over shipped modules.
  The v1 node cut could not see a facade (D2): round two built the facade the tool
  recommended and the v1 score moved 0.00 against a stated +25.71.
* ``f_propagation`` is the share of shipped modules that contain cryptography or call a
  module that does. The v1 ancestor ratio saturated at 0 on small repositories (D3).
* Only ``source`` files count (D4); callee-fixed algorithms are literal choices (D6).

Gates (8.2) run first. When one fires, no score is emitted and the reason is.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass

import networkx as nx

from quanta.config import Settings
from quanta.core.detect import DetectionResult
from quanta.core.models import (
    Coverage,
    CryptoSite,
    Deduction,
    Factor,
    InventorySummary,
    Provenance,
    Recommendation,
    Refusal,
    ScoreReport,
    ScoreStatus,
    UnmatchedName,
)
from quanta.core.ruleset_v2 import ALGORITHMS

_MAX_CITATIONS = 10

FORMULAS = {
    "call_sites": "1 / (1 + log10(1 + n))",
    "isolation_layer": "sum over crypto modules of (n_m / n)^2",
    "selection_source": "configured / (configured + literal)",
    "propagation_depth": "1 - (|C| + |D|) / |M|",
}


@dataclass(frozen=True)
class MetricInputs:
    touchpoints_by_module: Mapping[str, int]
    configured: int
    literal: int
    shipped_modules: frozenset[str]
    crypto_modules: frozenset[str]
    dependents: frozenset[str]

    @property
    def n(self) -> int:
        return sum(self.touchpoints_by_module.values())


def f_sites(n: int) -> float:
    return 1.0 / (1.0 + math.log10(1.0 + n))


def f_isolation(touchpoints_by_module: Mapping[str, int]) -> float:
    n = sum(touchpoints_by_module.values())
    if n == 0:
        return 1.0
    return sum((k / n) ** 2 for k in touchpoints_by_module.values() if k > 0)


def f_config(configured: int, literal: int) -> float:
    total = configured + literal
    return 1.0 if total == 0 else configured / total


def f_propagation(m: int, c: int, d: int) -> float:
    return 1.0 if m == 0 else 1.0 - (c + d) / m


def inputs_from(graph: nx.DiGraph) -> MetricInputs:
    """Metric inputs from a CDG whose nodes carry role, free, scored and selection."""
    shipped = frozenset(
        d["module"]
        for _, d in graph.nodes(data=True)
        if d.get("kind") == "module" and d.get("role") == "source"
    )
    touch: Counter[str] = Counter()
    configured = literal = 0
    for _, d in graph.nodes(data=True):
        if d.get("role") != "source":
            continue
        if d.get("kind") == "crypto_call" and d.get("scored", True):
            touch[d["module"]] += 1
            if d.get("selection") == "configured":
                configured += 1
            elif d.get("selection") == "literal":
                literal += 1
        elif d.get("kind") == "algo_literal" and d.get("free"):
            touch[d["module"]] += 1
            literal += 1
    crypto = frozenset(m for m, k in touch.items() if k > 0 and m in shipped)
    dependents: set[str] = set()
    for u, v, e in graph.edges(data=True):
        if e.get("kind") not in ("import", "call"):
            continue
        mu, mv = graph.nodes[u].get("module"), graph.nodes[v].get("module")
        if mu in shipped and mv in crypto and mu not in crypto:
            dependents.add(mu)
    return MetricInputs(
        touchpoints_by_module=dict(sorted(touch.items())),
        configured=configured,
        literal=literal,
        shipped_modules=shipped,
        crypto_modules=crypto,
        dependents=frozenset(dependents),
    )


# ---------------------------------------------------------------------------------------
# Gates (8.2)
# ---------------------------------------------------------------------------------------


def gate(
    inputs: MetricInputs,
    detection: DetectionResult,
    coverage: Coverage,
    settings: Settings,
) -> tuple[ScoreStatus, Refusal | None]:
    """Return ``(status, refusal)``. The first gate that fires decides."""
    m = settings.metric
    source_files = coverage.source_files
    unparseable_source = coverage.files_unparseable_source
    matched, unmatched = coverage.crypto_api_calls_matched, coverage.crypto_api_calls_unmatched
    ratio = coverage.coverage_ratio

    if source_files == 0:
        return "refused", Refusal(
            code="NO_SOURCE_FILES",
            message="No shipped Python code was found. Tests, docs and examples are not scored.",
        )
    if coverage.truncated:
        return "refused", Refusal(
            code="TRUNCATED_INPUT",
            message=(
                "The repository exceeded a size or time limit, so part of it was not read. "
                "A partial score would be misleading."
            ),
        )
    if unparseable_source / (source_files + unparseable_source) > m.max_unparseable_ratio:
        return "refused", Refusal(
            code="TOO_MANY_UNPARSEABLE",
            message="More than 10% of shipped files could not be parsed.",
            values={"unparseable": unparseable_source, "parsed": source_files},
        )
    total = matched + unmatched
    if (matched == 0 and unmatched > 0) or (
        total >= m.coverage_min_sample and ratio is not None and ratio < m.coverage_min
    ):
        return "refused", Refusal(
            code="LOW_DETECTION_COVERAGE",
            message=(
                f"Quanta recognised {matched} of {total} calls into cryptography libraries. "
                f"Below {int(m.coverage_min * 100)}%, the score would describe a small part "
                "of the code."
            ),
            values={"matched": matched, "unmatched": unmatched, "coverage_ratio": ratio},
        )
    if inputs.n == 0:
        return "no_crypto_detected", None
    if len(inputs.shipped_modules) < m.min_source_modules:
        return "refused", Refusal(
            code="TOO_FEW_MODULES",
            message=(
                f"Architecture factors need at least {m.min_source_modules} shipped modules; "
                f"this repository has {len(inputs.shipped_modules)}."
            ),
            values={"source_modules": len(inputs.shipped_modules)},
        )
    return "scored", None


# ---------------------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------------------


def _touchpoint_sites(detection: DetectionResult) -> list[CryptoSite]:
    return [
        s
        for s in detection.sites
        if s.role == "source"
        and ((s.kind == "crypto_call" and s.scored) or (s.kind == "algo_literal" and s.free))
    ]


def _cite(sites: list[CryptoSite]) -> tuple[str, ...]:
    out: list[str] = []
    for s in sorted(sites, key=lambda s: (s.file, s.line)):
        if s.citation not in out:
            out.append(s.citation)
        if len(out) >= _MAX_CITATIONS:
            break
    return tuple(out)


def inventory_summary(detection: DetectionResult) -> InventorySummary:
    calls = [s for s in detection.sites if s.kind == "crypto_call"]
    by_algorithm: Counter[str] = Counter()
    by_category: Counter[str] = Counter()
    pq = 0
    for s in calls:
        for a in s.algorithms or ((s.algorithm,) if s.algorithm else ()):
            by_algorithm[a] += 1
            info = ALGORITHMS.get(a)
            if info and info.pq:
                pq += 1
        if s.category:
            by_category[s.category] += 1
    return InventorySummary(
        weak=sum(1 for s in detection.sites if s.weak),
        quantum_vulnerable=sum(1 for s in calls if s.quantum_vulnerable),
        pq=pq,
        by_algorithm=dict(sorted(by_algorithm.items())),
        by_category=dict(sorted(by_category.items())),
    )


def coverage_from(detection: DetectionResult, *, truncated: bool) -> Coverage:
    by_role: Counter[str] = Counter(
        dict.fromkeys(("source", "test", "docs", "example", "vendored", "tooling"), 0)
    )
    for s in detection.crypto_calls:
        by_role[s.role] += 1
    unparseable_source = sum(1 for u in detection.unparseable if _role_of(u.file) == "source")
    ratio = detection.coverage_ratio
    top = sorted(detection.unmatched_names.items(), key=lambda kv: (-kv[1], kv[0]))[:20]
    return Coverage(
        files_scanned=detection.files_scanned,
        files_unparseable=len(detection.unparseable),
        files_unparseable_source=unparseable_source,
        truncated=truncated,
        source_files=detection.source_files,
        sites_by_role=dict(by_role),
        touchpoints=len(_touchpoint_sites(detection)),
        crypto_api_calls_matched=detection.api_matched,
        crypto_api_calls_unmatched=detection.api_unmatched,
        coverage_ratio=ratio,
        unmatched_top=tuple(UnmatchedName(name=n, count=c) for n, c in top),
    )


def _role_of(path: str) -> str:
    from quanta.core.roles import classify_role

    return classify_role(path)


def compute_v2(
    detection: DetectionResult,
    graph: nx.DiGraph,
    provenance: Provenance,
    coverage: Coverage,
    settings: Settings,
) -> ScoreReport:
    """Gate, then score, with a cited deduction for every point removed."""
    weights = settings.weights
    weights.validate_sum()
    inputs = inputs_from(graph)
    summary = inventory_summary(detection)
    provenance = provenance.model_copy(
        update={"metric_version": "metric-v2", "weights_version": weights.version}
    )
    coverage = coverage.model_copy(update={"touchpoints": inputs.n})

    status, refusal = gate(inputs, detection, coverage, settings)
    if status != "scored":
        return ScoreReport(
            status=status,
            refusal=refusal,
            provenance=provenance,
            agility_score=None,
            coverage=coverage,
            inventory_summary=summary,
            recommendations=tuple(_advisories(detection)),
        )

    m, c, d = len(inputs.shipped_modules), len(inputs.crypto_modules), len(inputs.dependents)
    values = {
        "call_sites": (f_sites(inputs.n), weights.f_sites, inputs.n, {"n": inputs.n}),
        "isolation_layer": (
            f_isolation(inputs.touchpoints_by_module),
            weights.f_isolation,
            round(1.0 / max(f_isolation(inputs.touchpoints_by_module), 1e-9), 6),
            {"crypto_modules": c, "touchpoints": inputs.n},
        ),
        "selection_source": (
            f_config(inputs.configured, inputs.literal),
            weights.f_config,
            "none" if inputs.configured + inputs.literal == 0 else "configured_share",
            {"configured": inputs.configured, "literal": inputs.literal},
        ),
        "propagation_depth": (
            f_propagation(m, c, d),
            weights.f_propagation,
            c + d,
            {"shipped_modules": m, "crypto_modules": c, "dependents": d},
        ),
    }
    factors: dict[str, Factor] = {}
    total = 0.0
    for key, (value, weight, raw, factor_inputs) in values.items():
        value = max(0.0, min(1.0, value))
        contribution = 100.0 * weight * value
        total += contribution
        factors[key] = Factor(
            raw=raw,
            normalised=value,
            weight=weight,
            contribution=contribution,
            formula=FORMULAS[key],
            inputs=factor_inputs,
        )

    deductions = _deductions(detection, graph, inputs, factors)
    recommendations = _recommendations(detection, deductions)
    return ScoreReport(
        status="scored",
        provenance=provenance,
        agility_score=max(0.0, min(100.0, total)),
        factors=factors,
        deductions=tuple(deductions),
        recommendations=tuple(recommendations),
        coverage=coverage,
        inventory_summary=summary,
    )


def _deductions(
    detection: DetectionResult,
    graph: nx.DiGraph,
    inputs: MetricInputs,
    factors: dict[str, Factor],
) -> list[Deduction]:
    out: list[Deduction] = []
    touch = _touchpoint_sites(detection)
    n = inputs.n

    f = factors["call_sites"]
    if f.normalised < 1.0 and touch:
        out.append(
            Deduction(
                factor="call_sites",
                points=100.0 * f.weight * (1.0 - f.normalised),
                reason=(
                    f"{n} cryptographic touchpoint{'s' if n != 1 else ''} in shipped code "
                    "must each be edited to change an algorithm."
                ),
                citations=_cite(touch),
            )
        )

    f = factors["isolation_layer"]
    if f.normalised < 1.0 and touch:
        counts = inputs.touchpoints_by_module
        dominant = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        outside = [s for s in touch if s.module != dominant]
        k = len([v for v in counts.values() if v > 0])
        out.append(
            Deduction(
                factor="isolation_layer",
                points=100.0 * f.weight * (1.0 - f.normalised),
                reason=(
                    f"Cryptography is spread over {k} modules (effective number "
                    f"{1.0 / f.normalised:.1f}). {n - counts[dominant]} of {n} touchpoints "
                    f"are outside {dominant}."
                ),
                citations=_cite(outside) or _cite(touch),
            )
        )

    f = factors["selection_source"]
    if f.normalised < 1.0:
        literal_sites = [
            s for s in touch if (s.kind == "crypto_call" and s.selection == "literal") or s.free
        ]
        if literal_sites:
            total = inputs.configured + inputs.literal
            out.append(
                Deduction(
                    factor="selection_source",
                    points=100.0 * f.weight * (1.0 - f.normalised),
                    reason=f"{inputs.literal} of {total} algorithm choices are fixed in code.",
                    citations=_cite(literal_sites),
                )
            )

    f = factors["propagation_depth"]
    if f.normalised < 1.0 and touch:
        edges: list[tuple[str, int]] = []
        for u, v, e in graph.edges(data=True):
            if e.get("kind") not in ("import", "call"):
                continue
            mu, mv = graph.nodes[u].get("module"), graph.nodes[v].get("module")
            if mu in inputs.dependents and mv in inputs.crypto_modules and e.get("file"):
                edges.append((e["file"], int(e.get("line", 0))))
        citations = tuple(dict.fromkeys(f"{fl}:{ln}" for fl, ln in sorted(edges)))[:_MAX_CITATIONS]
        c, d, m = len(inputs.crypto_modules), len(inputs.dependents), len(inputs.shipped_modules)
        out.append(
            Deduction(
                factor="propagation_depth",
                points=100.0 * f.weight * (1.0 - f.normalised),
                reason=(
                    f"{c + d} of {m} shipped modules contain cryptography or call a module "
                    "that does."
                ),
                citations=citations or _cite(touch),
            )
        )
    return out


def _advisories(detection: DetectionResult) -> list[Recommendation]:
    out: list[Recommendation] = []
    weak = [s for s in detection.sites if s.weak and s.role == "source"]
    if weak:
        out.append(
            Recommendation(
                action="Replace broken primitives (MD5, SHA-1, DES, 3DES, RC4, ECB mode).",
                estimated_score_gain=0.0,
                affected_sites=len(weak),
                pattern="P0",
                bound="not scored; a security fix, and compatibility-changing",
            )
        )
    quantum = [s for s in detection.crypto_calls if s.quantum_vulnerable and s.role == "source"]
    if quantum:
        out.append(
            Recommendation(
                action=(
                    "Plan migration of quantum-vulnerable key establishment and signatures "
                    "(ML-KEM, ML-DSA, ideally hybrid)."
                ),
                estimated_score_gain=0.0,
                affected_sites=len(quantum),
                pattern="P3",
                bound="not scored; needs both ends of a protocol",
            )
        )
    return out


def _recommendations(
    detection: DetectionResult, deductions: list[Deduction]
) -> list[Recommendation]:
    by_factor = {d.factor: d for d in deductions}
    out: list[Recommendation] = []
    if "isolation_layer" in by_factor:
        out.append(
            Recommendation(
                action="Move cryptographic calls into one module (pattern P1).",
                estimated_score_gain=by_factor["isolation_layer"].points,
                affected_sites=len(_touchpoint_sites(detection)),
                pattern="P1",
            )
        )
    if "selection_source" in by_factor:
        out.append(
            Recommendation(
                action="Read algorithm choices from a checked policy (pattern P2).",
                estimated_score_gain=by_factor["selection_source"].points,
                affected_sites=sum(
                    1 for s in _touchpoint_sites(detection) if s.selection == "literal"
                ),
                pattern="P2",
            )
        )
    return out + _advisories(detection)
