"""The three vault variants under metric-v2 (Master Plan 8.8, 8.9, T2.1).

Same application, same eight cryptographic calls, three architectures. The v1 tests that
pinned the node cut and the saturating propagation factor were removed with metric v1
(Master Plan 8.7); round two showed v1 could not reward the facade it recommended.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from quanta.core.analyze import AnalysisOutcome, analyze_path
from quanta.core.models import Provenance
from quanta.resources import asset_path

VARIANTS = ("scattered", "facade", "configured")

PROVENANCE = Provenance(
    repo="demo/vault",
    commit_sha="0" * 40,
    analyzer_version="test",
    crypto_ruleset_version="test",
)


@pytest.fixture(scope="module")
def measured() -> dict[str, AnalysisOutcome]:
    return {v: analyze_path(asset_path(f"demo/repos/vault-{v}"), PROVENANCE) for v in VARIANTS}


def test_every_variant_is_scored(measured: dict[str, AnalysisOutcome]) -> None:
    for outcome in measured.values():
        assert outcome.score.status == "scored"


def test_all_variants_have_the_same_eight_touchpoints(measured: dict[str, AnalysisOutcome]) -> None:
    counts = {v: o.score.coverage.touchpoints for v, o in measured.items()}
    assert set(counts.values()) == {8}, counts


def test_the_score_climbs_across_the_three_architectures(
    measured: dict[str, AnalysisOutcome],
) -> None:
    s = {v: measured[v].score.agility_score for v in VARIANTS}
    assert s["scattered"] < s["facade"] < s["configured"]  # type: ignore[operator]
    assert s["facade"] - s["scattered"] >= 15.0  # type: ignore[operator]
    assert s["configured"] - s["facade"] >= 5.0  # type: ignore[operator]


def test_the_facade_is_seen_by_isolation(measured: dict[str, AnalysisOutcome]) -> None:
    scattered = measured["scattered"].score.factors["isolation_layer"]
    facade = measured["facade"].score.factors["isolation_layer"]
    assert round(scattered.normalised, 6) == 0.21875
    assert facade.normalised == 1.0


def test_only_the_configured_variant_reads_its_hash_choices_from_config(
    measured: dict[str, AnalysisOutcome],
) -> None:
    config = {v: measured[v].score.factors["selection_source"].inputs for v in VARIANTS}
    assert config["scattered"] == {"configured": 0, "literal": 8}
    assert config["facade"] == {"configured": 0, "literal": 8}
    assert config["configured"] == {"configured": 4, "literal": 4}


def test_the_scattered_variant_reproduces_the_worked_example(
    measured: dict[str, AnalysisOutcome],
) -> None:
    """Master Plan 8.8: 30.4851 for the scattered variant."""
    assert round(measured["scattered"].score.agility_score or 0, 4) == 30.4851


def test_the_facade_recommendation_bounds_the_isolation_gain(
    measured: dict[str, AnalysisOutcome],
) -> None:
    """The P1 upper bound is the isolation deduction, and the facade recovers all of it."""
    scattered, facade = measured["scattered"].score, measured["facade"].score
    bound = next(r for r in scattered.recommendations if r.pattern == "P1").estimated_score_gain
    gained = (
        facade.factors["isolation_layer"].contribution
        - scattered.factors["isolation_layer"].contribution
    )
    assert gained == pytest.approx(bound, abs=1e-6)


def test_measured_scores_are_published(measured: dict[str, AnalysisOutcome]) -> None:
    """docs/research/metric-v2-variants.json holds the three measured scores."""
    published = json.loads(asset_path("docs/research/metric-v2-variants.json").read_text())
    for v in VARIANTS:
        assert published[v] == measured[v].score.agility_score


def test_variants_are_equivalent_programs() -> None:
    """The facade and configured variants move calls; they must not drop any file."""
    names = {
        v: sorted(p.name for p in Path(asset_path(f"demo/repos/vault-{v}/vault")).glob("*.py"))
        for v in VARIANTS
    }
    assert set(names["scattered"]) | {"_crypto_facade.py"} == set(names["facade"])
    assert names["facade"] == names["configured"]
