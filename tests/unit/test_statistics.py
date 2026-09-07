from __future__ import annotations

import json
from pathlib import Path

import pytest

from quanta.errors import Reject
from quanta.stats.analysis import (
    bootstrap,
    collinearity,
    load_results,
    load_scores,
    mcnemar,
    sensitivity,
)


def result(repo: str, site: str, engine: str, status: str) -> dict[str, str]:
    return {"repo": repo, "site_id": site, "engine": engine, "status": status, "pattern": "p0"}


def test_mcnemar_keeps_unverified_out_of_binary_denominator() -> None:
    rows = [
        result("r", "1", "e0", "passed"),
        result("r", "1", "e1", "failed"),
        result("r", "2", "e0", "unverified"),
        result("r", "2", "e1", "passed"),
    ]
    pair = mcnemar(rows)["patterns"]["p0"][0]
    assert pair["paired_verified_sites"] == 1
    assert pair["excluded_sites"] == 1
    assert pair["left_only_passed"] == 1 and pair["right_only_passed"] == 0
    assert pair["p_value"] == 1


def test_cluster_bootstrap_retains_repository_clusters_and_is_reproducible() -> None:
    rows = [result("a", str(i), "e0", "passed") for i in range(30)]
    rows += [result("b", str(i), "e0", "failed") for i in range(30)]
    first = bootstrap(rows, iterations=1000)
    assert first == bootstrap(rows, iterations=1000)
    estimate = first["results"][0]
    # Resampling individual sites would falsely narrow this interval near 0.5.
    assert estimate["ci95"] == [0.0, 1.0]
    assert estimate["verified_success_rate"] == 0.5
    assert estimate["repositories"] == 2


def test_duplicate_result_is_rejected(tmp_path: Path) -> None:
    file = tmp_path / "data.jsonl"
    row = json.dumps(result("r", "1", "e0", "passed"))
    file.write_text(row + "\n" + row + "\n")
    with pytest.raises(Reject, match="duplicate"):
        load_results(file)


def test_weight_reports_are_reproducible_and_never_mutate_scores() -> None:
    root = Path(__file__).parents[2] / "demo/corpus"
    scores = load_scores(root)
    original = [s.model_dump_json() for s in scores]
    report = sensitivity(scores)
    assert len(report["cases"]) == 8
    assert all(sum(case["weights"].values()) == pytest.approx(1) for case in report["cases"])
    assert collinearity(scores)["matrix"]
    assert report == sensitivity(scores)
    assert original == [s.model_dump_json() for s in scores]
