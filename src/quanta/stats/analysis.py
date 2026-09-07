"""Paired, repository-clustered and weight-sensitivity analyses with explicit denominators."""

from __future__ import annotations

import itertools
import math
from pathlib import Path
from typing import Any

from quanta.bench.dataset import read_jsonl
from quanta.config import get_settings
from quanta.core.models import ScoreReport, write_canonical_json
from quanta.errors import Reject

ENGINES = ("e0", "e1", "e2")
FACTORS = ("call_sites", "isolation_layer", "selection_source", "propagation_depth")
VERIFIED = frozenset({"passed", "failed"})


def load_results(path: Path) -> list[dict[str, Any]]:
    rows = read_jsonl(path)
    seen: set[tuple[str, ...]] = set()
    for row in rows:
        key = tuple(str(row.get(k, "")) for k in ("repo", "site_id", "pattern", "engine"))
        if (
            not all(key)
            or key in seen
            or row.get("engine") not in ENGINES
            or row.get("status") not in {"passed", "failed", "unverified", "refused"}
        ):
            raise Reject("BENCHMARK_INVALID", "invalid or duplicate engine result")
        seen.add(key)
    if not rows:
        raise Reject("BENCHMARK_INVALID", "no engine results supplied")
    return rows


def mcnemar(rows: list[dict[str, Any]]) -> dict[str, Any]:
    from scipy.stats import binomtest

    results: dict[str, Any] = {}
    for pattern in sorted({r["pattern"] for r in rows}):
        subset = [r for r in rows if r["pattern"] == pattern]
        by_site: dict[tuple[str, str], dict[str, str]] = {}
        for row in subset:
            by_site.setdefault((row["repo"], row["site_id"]), {})[row["engine"]] = row["status"]
        pairs = []
        for left, right in itertools.combinations(ENGINES, 2):
            b = c = concordant = excluded = 0
            for outcomes in by_site.values():
                a, z = outcomes.get(left), outcomes.get(right)
                if a not in VERIFIED or z not in VERIFIED:
                    excluded += 1
                    continue
                b += int(a == "passed" and z == "failed")
                c += int(a == "failed" and z == "passed")
                concordant += int(a == z)
            pairs.append(
                {
                    "engines": [left, right],
                    "left_only_passed": b,
                    "right_only_passed": c,
                    "paired_verified_sites": b + c + concordant,
                    "excluded_sites": excluded,
                    "p_value": float(binomtest(b, b + c, 0.5).pvalue)
                    if b + c
                    else (1.0 if concordant else None),
                }
            )
        results[pattern] = pairs
    return {
        "method": "exact two-sided McNemar",
        "patterns": results,
        "limitation": "Site-level test assumes independence; "
        "sites within repositories may correlate.",
        "unverified_policy": "excluded from binary pairs and counted explicitly",
    }


def bootstrap(
    rows: list[dict[str, Any]], *, iterations: int = 10000, seed: int = 20260801
) -> dict[str, Any]:
    import numpy as np

    if iterations < 100:
        raise Reject("BENCHMARK_INVALID", "bootstrap requires at least 100 iterations")
    output = []
    for pattern in sorted({r["pattern"] for r in rows}):
        for engine in ENGINES:
            subset = [r for r in rows if r["pattern"] == pattern and r["engine"] == engine]
            repositories = sorted({r["repo"] for r in subset})
            counts = np.array(
                [
                    [
                        sum(r["repo"] == repo and r["status"] == "passed" for r in subset),
                        sum(r["repo"] == repo and r["status"] in VERIFIED for r in subset),
                    ]
                    for repo in repositories
                ],
                dtype=float,
            )
            excluded = {
                kind: sum(r["status"] == kind for r in subset) for kind in ("unverified", "refused")
            }
            if len(repositories) < 2 or counts[:, 1].sum() == 0:
                output.append(
                    {
                        "pattern": pattern,
                        "engine": engine,
                        "repositories": len(repositories),
                        "ci95": None,
                        "reason": "at least two repositories and verified outcomes required",
                        "excluded": excluded,
                    }
                )
                continue
            rng = np.random.default_rng(seed)
            draws = rng.integers(0, len(repositories), size=(iterations, len(repositories)))
            totals = counts[draws].sum(axis=1)
            valid = totals[:, 1] > 0
            rates = totals[valid, 0] / totals[valid, 1]
            output.append(
                {
                    "pattern": pattern,
                    "engine": engine,
                    "repositories": len(repositories),
                    "verified_success_rate": float(counts[:, 0].sum() / counts[:, 1].sum()),
                    "ci95": [float(x) for x in np.quantile(rates, [0.025, 0.975])],
                    "excluded": excluded,
                    "empty_resamples": int((~valid).sum()),
                }
            )
    return {
        "method": "repository cluster percentile bootstrap",
        "seed": seed,
        "iterations": iterations,
        "results": output,
    }


def load_scores(directory: Path) -> list[ScoreReport]:
    scores = [
        ScoreReport.model_validate_json(p.read_text())
        for p in sorted(directory.rglob("score.json"))
    ]
    if len(scores) < 2:
        raise Reject("BENCHMARK_INVALID", "at least two repository scores are required")
    if len({s.provenance.repo for s in scores}) != len(scores):
        raise Reject("BENCHMARK_INVALID", "supply exactly one score per repository")
    return scores


def _rho(left: list[float], right: list[float]) -> float | None:
    from scipy.stats import spearmanr

    if len(set(left)) < 2 or len(set(right)) < 2:
        return None
    value = float(spearmanr(left, right).statistic)
    return value if math.isfinite(value) else None


def sensitivity(scores: list[ScoreReport], delta: float = 0.30) -> dict[str, Any]:
    if not 0 < delta < 1:
        raise Reject("BENCHMARK_INVALID", "sensitivity delta must lie between zero and one")
    weights = [scores[0].factors[k].weight for k in FACTORS]
    if any([s.factors[k].weight for k in FACTORS] != weights for s in scores):
        raise Reject("BENCHMARK_INVALID", "all scores must use identical pre-registered weights")
    baseline = [s.agility_score for s in scores]
    cases = []
    for index, factor in enumerate(FACTORS):
        for direction in (-1, 1):
            varied = weights.copy()
            varied[index] *= 1 + direction * delta
            if varied[index] >= 1 or weights[index] >= 1:
                raise Reject("BENCHMARK_INVALID", "weight perturbation is not normalisable")
            for other in range(len(weights)):
                if other != index:
                    varied[other] *= (1 - varied[index]) / (1 - weights[index])
            values = [
                100 * sum(w * s.factors[k].normalised for w, k in zip(varied, FACTORS, strict=True))
                for s in scores
            ]
            cases.append(
                {
                    "factor": factor,
                    "perturbation": direction * delta,
                    "weights": dict(zip(FACTORS, varied, strict=True)),
                    "spearman_rho": _rho(baseline, values),
                    "scores": {
                        s.provenance.repo: value for s, value in zip(scores, values, strict=True)
                    },
                }
            )
    return {
        "repositories": len(scores),
        "delta": delta,
        "cases": cases,
        "undefined_correlation": "null means a constant ranking",
    }


def collinearity(scores: list[ScoreReport], threshold: float = 0.8) -> dict[str, Any]:
    values = {k: [s.factors[k].normalised for s in scores] for k in FACTORS}
    matrix = {
        left: {right: _rho(values[left], values[right]) for right in FACTORS} for left in FACTORS
    }
    flagged = [
        {"factors": [a, b], "rho": matrix[a][b]}
        for a, b in itertools.combinations(FACTORS, 2)
        if (rho := matrix[a][b]) is not None and abs(rho) > threshold
    ]
    return {
        "method": "Spearman factor correlation",
        "matrix": matrix,
        "threshold": threshold,
        "flagged_pairs": flagged,
        "action": "Review correlated factors; this report never changes pre-registered weights.",
    }


def run_statistics(command: str, data: Path, scores: Path, out: Path) -> list[Path]:
    cfg = get_settings().stats
    commands = ("mcnemar", "bootstrap", "sensitivity", "collinearity")
    if command not in (*commands, "all"):
        raise Reject("BENCHMARK_INVALID", "unknown statistics command")
    # Validate every input before writing any partial 'all' run.
    rows = load_results(data) if command in {"mcnemar", "bootstrap", "all"} else []
    reports = load_scores(scores) if command in {"sensitivity", "collinearity", "all"} else []
    output = []
    for name in commands if command == "all" else (command,):
        if name == "mcnemar":
            result = mcnemar(rows)
        elif name == "bootstrap":
            result = bootstrap(rows, iterations=cfg.bootstrap_iterations)
        elif name == "sensitivity":
            result = sensitivity(reports, cfg.sensitivity_delta)
        else:
            result = collinearity(reports, cfg.collinearity_threshold)
        path = out / f"{name}.json"
        write_canonical_json(path, result)
        output.append(path)
    return output
