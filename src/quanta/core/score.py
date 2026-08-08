"""Agility Score computation (§5.3.3).

``S = 100 × (w₁·f_sites + w₂·f_isolation + w₃·f_config + w₄·f_propagation)``

Weights are **pre-registered** (§8.2) and git-tagged ``weights-v1``. Tuning them after
observing engine results is overfitting and would invalidate the score entirely (§11.2),
so they are loaded from configuration and their sum is asserted rather than renormalised.

Every deduction carries at least one ``file:line`` citation. That is not a nicety —
PROC-08 makes a score without a traceable cause a defect, and the model layer refuses to
construct one, so this module cannot regress into emitting bare numbers.

The four factors are expected to be **partially collinear**: an insulation layer
mechanically implies fewer call sites and shallower propagation. §5.3.3 requires that be
tested over the corpus rather than assumed away, which is the ``stats`` phase's job. Until
then the risk is documented here, not hidden.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import networkx as nx

from quanta.config import Settings, get_settings
from quanta.core.detect import DetectionResult
from quanta.core.graph import blast_radius, crypto_nodes, isolation_cut_size, module_nodes_of
from quanta.core.models import (
    Coverage,
    Deduction,
    Factor,
    Provenance,
    Recommendation,
    ScoreReport,
)

#: How many citations to attach per deduction. Enough to be actionable; not so many that
#: the report becomes a file listing.
_MAX_CITATIONS = 10


@dataclass(frozen=True)
class FactorValue:
    raw: int | float | bool | str
    normalised: float


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


# ---------------------------------------------------------------------------------------
# The four factors
# ---------------------------------------------------------------------------------------


def factor_sites(graph: nx.DiGraph) -> FactorValue:
    """``1 / (1 + log₁₀(1 + n))`` — one site ≈ 1.0, hundreds → near 0."""
    n = len(crypto_nodes(graph))
    return FactorValue(raw=n, normalised=_clamp(1.0 / (1.0 + math.log10(1.0 + n))))


def factor_isolation(graph: nx.DiGraph) -> FactorValue:
    """``1 / (1 + cut_size)`` — a small cut means a facade exists.

    ``raw`` is reported as a bool, matching the ``score.json`` example in §5.1.4, where
    ``isolation_layer.raw`` is ``false``. A cut of 1 or 2 nodes is the signature of a
    genuine insulation layer; anything wider means cryptography is reachable from many
    independent places.
    """
    cut, disconnected = isolation_cut_size(graph)
    if disconnected:
        # Nothing depends on the cryptography (or there is none). Treated as isolated.
        return FactorValue(raw=True, normalised=1.0)
    return FactorValue(raw=cut <= 2, normalised=_clamp(1.0 / (1.0 + cut)))


def factor_config(detection: DetectionResult) -> FactorValue:
    """Fraction of algorithm selections that come from configuration, not a literal.

    This is policy/mechanism separation, which NIST CSWP 39 names as a determinant of
    agility: an algorithm read from configuration is swapped by editing configuration,
    while a hard-coded one requires a code change at every site.
    """
    literals = len(detection.algo_literals)
    configured = len(detection.config_reads)
    total = literals + configured
    if total == 0:
        # Nothing selects an algorithm anywhere; there is nothing to hold against the
        # repository, so this factor must not manufacture a deduction.
        return FactorValue(raw="none", normalised=1.0)
    ratio = configured / total
    return FactorValue(raw="config" if ratio >= 0.5 else "hardcoded", normalised=_clamp(ratio))


def factor_propagation(graph: nx.DiGraph) -> FactorValue:
    """``1 − (ancestors ÷ module count)`` — indirect blast radius.

    ``raw`` is the size of the union of ancestors over every crypto node: how much of the
    graph can reach cryptography, and so might have to change with it.

    The ratio is clamped to [0, 1]. §5.3.3 divides an ancestor count (which includes
    function and module nodes) by a module count, so the quotient exceeds 1 whenever a
    repository has more crypto-reaching scopes than modules — which is normal for small
    repositories. Clamping saturates those at 0 rather than producing a negative factor
    and a nonsensical score; the discrimination this factor provides therefore appears
    on multi-module repositories, which is where propagation is a meaningful question.
    """
    crypto = crypto_nodes(graph)
    if not crypto:
        return FactorValue(raw=0, normalised=1.0)

    ancestors: set[str] = set()
    for node in crypto:
        ancestors |= nx.ancestors(graph, node)

    modules = max(1, len(module_nodes_of(graph)))
    return FactorValue(raw=len(ancestors), normalised=_clamp(1.0 - len(ancestors) / modules))


# ---------------------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------------------


def _citations(detection: DetectionResult, kinds: tuple[str, ...]) -> tuple[str, ...]:
    seen: list[str] = []
    for site in detection.sites:
        if site.kind in kinds:
            citation = site.citation
            if citation not in seen:
                seen.append(citation)
        if len(seen) >= _MAX_CITATIONS:
            break
    return tuple(seen)


def compute_score(
    detection: DetectionResult,
    graph: nx.DiGraph,
    provenance: Provenance,
    coverage: Coverage,
    settings: Settings | None = None,
) -> ScoreReport:
    """Compute the Agility Score with a cited deduction for every point removed."""
    cfg = settings or get_settings()
    weights = cfg.weights
    weights.validate_sum()

    values = {
        "call_sites": (factor_sites(graph), weights.f_sites),
        "isolation_layer": (factor_isolation(graph), weights.f_isolation),
        "selection_source": (factor_config(detection), weights.f_config),
        "propagation_depth": (factor_propagation(graph), weights.f_propagation),
    }

    factors: dict[str, Factor] = {}
    total = 0.0
    for name, (value, weight) in values.items():
        contribution = 100.0 * weight * value.normalised
        total += contribution
        factors[name] = Factor(
            raw=value.raw,
            normalised=value.normalised,
            weight=weight,
            contribution=contribution,
        )

    deductions = _build_deductions(detection, graph, values)
    recommendations = _build_recommendations(detection, values, deductions)

    return ScoreReport(
        provenance=provenance,
        agility_score=_clamp(total / 100.0) * 100.0,
        factors=factors,
        deductions=tuple(deductions),
        recommendations=tuple(recommendations),
        coverage=coverage,
    )


def _build_deductions(
    detection: DetectionResult,
    graph: nx.DiGraph,
    values: dict[str, tuple[FactorValue, float]],
) -> list[Deduction]:
    """One deduction per factor that lost points, each with concrete evidence.

    A factor at full marks produces no deduction — an entry reading "0.0 points removed"
    is noise, and the report is meant to be read.
    """
    deductions: list[Deduction] = []

    call_citations = _citations(detection, ("crypto_call",))
    selector_citations = _citations(detection, ("algo_literal",)) or call_citations

    site_value, site_weight = values["call_sites"]
    if site_value.normalised < 1.0 and call_citations:
        n = len(crypto_nodes(graph))
        deductions.append(
            Deduction(
                factor="call_sites",
                points=100.0 * site_weight * (1.0 - site_value.normalised),
                reason=(
                    f"{n} cryptographic call site{'s' if n != 1 else ''} must each be "
                    f"edited to change algorithm"
                ),
                citations=call_citations,
            )
        )

    iso_value, iso_weight = values["isolation_layer"]
    if iso_value.normalised < 1.0 and call_citations:
        cut, _ = isolation_cut_size(graph)
        modules = len({s.module for s in detection.crypto_calls})
        deductions.append(
            Deduction(
                factor="isolation_layer",
                points=100.0 * iso_weight * (1.0 - iso_value.normalised),
                reason=(
                    f"Crypto APIs invoked directly from {modules} module"
                    f"{'s' if modules != 1 else ''} with no common wrapper; "
                    f"{cut} nodes must be cut to decouple cryptography"
                ),
                citations=call_citations,
            )
        )

    cfg_value, cfg_weight = values["selection_source"]
    if cfg_value.normalised < 1.0 and selector_citations:
        literals = len(detection.algo_literals)
        deductions.append(
            Deduction(
                factor="selection_source",
                points=100.0 * cfg_weight * (1.0 - cfg_value.normalised),
                reason=(
                    f"{literals} algorithm selection{'s are' if literals != 1 else ' is'} "
                    f"hard-coded rather than read from configuration"
                ),
                citations=selector_citations,
            )
        )

    prop_value, prop_weight = values["propagation_depth"]
    if prop_value.normalised < 1.0 and call_citations:
        deepest = _deepest_sites(detection, graph)
        deductions.append(
            Deduction(
                factor="propagation_depth",
                points=100.0 * prop_weight * (1.0 - prop_value.normalised),
                reason=(
                    f"{prop_value.raw} graph nodes can reach cryptography, so a change "
                    f"propagates well beyond the call sites themselves"
                ),
                citations=deepest or call_citations,
            )
        )

    return deductions


def _deepest_sites(detection: DetectionResult, graph: nx.DiGraph) -> tuple[str, ...]:
    """Cite the crypto sites with the widest blast radius — where propagation hurts most."""
    scored = [
        (blast_radius(graph, s.site_id), s.citation)
        for s in detection.crypto_calls
        if graph.has_node(s.site_id)
    ]
    scored.sort(key=lambda pair: (-pair[0], pair[1]))
    out: list[str] = []
    for _, citation in scored:
        if citation not in out:
            out.append(citation)
        if len(out) >= _MAX_CITATIONS:
            break
    return tuple(out)


def _build_recommendations(
    detection: DetectionResult,
    values: dict[str, tuple[FactorValue, float]],
    deductions: list[Deduction],
) -> list[Recommendation]:
    """Concrete refactors, each with the points it would recover.

    The estimate is the *upper bound* of what the corresponding factor is currently
    losing. It is a bound rather than a prediction, and the report labels it as such —
    an over-confident number here would be exactly the "dangerously low estimate an
    organisation might act on" §1.4 warns against.
    """
    by_factor = {d.factor: d.points for d in deductions}
    recommendations: list[Recommendation] = []
    sites = len(detection.crypto_calls)

    if "isolation_layer" in by_factor:
        recommendations.append(
            Recommendation(
                action=(
                    "Introduce a crypto facade module fronting the cryptographic "
                    "primitives, so algorithm changes are made in one place"
                ),
                estimated_score_gain=by_factor["isolation_layer"],
                affected_sites=sites,
            )
        )

    if "selection_source" in by_factor:
        recommendations.append(
            Recommendation(
                action=(
                    "Move algorithm selection into configuration so the algorithm is "
                    "policy rather than a code literal (NIST CSWP 39)"
                ),
                estimated_score_gain=by_factor["selection_source"],
                affected_sites=len(detection.algo_literals),
            )
        )

    weak = [s for s in detection.sites if s.weak]
    if weak:
        recommendations.append(
            Recommendation(
                action=(
                    "Replace broken primitives (MD5/SHA1/3DES/RC4); these are weak today, "
                    "independently of any quantum adversary"
                ),
                estimated_score_gain=0.0,
                affected_sites=len(weak),
            )
        )

    quantum = [s for s in detection.crypto_calls if s.quantum_vulnerable]
    if quantum:
        recommendations.append(
            Recommendation(
                action=(
                    "Plan migration of quantum-vulnerable key establishment and signatures "
                    "to ML-KEM / ML-DSA, ideally via a hybrid construction"
                ),
                estimated_score_gain=0.0,
                affected_sites=len(quantum),
            )
        )

    return recommendations
