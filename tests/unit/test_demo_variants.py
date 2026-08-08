"""The demo's central claim, asserted (`demo/repos/vault-*`).

Act 4 tells an examining committee: *the same six cryptographic calls, three
architectures, and the score moves.* If a future change to the scorer flattens that, the
right outcome is a failing test — not a presenter discovering it live.

The three variants are a controlled comparison by construction: identical module count,
identical crypto call count, identical file layout. Only the architecture differs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quanta.core.detect import DetectionResult, detect_repository
from quanta.core.graph import build_cdg, isolation_cut_size
from quanta.core.ingest import walk_repository
from quanta.core.models import Coverage, Provenance, ScoreReport
from quanta.core.score import compute_score

REPOS = Path(__file__).resolve().parents[2] / "demo" / "repos"

SCATTERED = "vault-scattered"
FACADE = "vault-facade"
CONFIGURED = "vault-configured"
VARIANTS = (SCATTERED, FACADE, CONFIGURED)

PROVENANCE = Provenance(
    repo="demo/vault",
    commit_sha="0" * 40,
    analyzer_version="0.1.0",
    crypto_ruleset_version="2026.08.01",
)


def analyse(variant: str) -> tuple[DetectionResult, ScoreReport, int]:
    root = REPOS / variant
    detection = detect_repository(walk_repository(root).files, root)
    graph = build_cdg(detection)
    cut, _ = isolation_cut_size(graph)
    score = compute_score(
        detection, graph, PROVENANCE, Coverage(files_scanned=detection.files_scanned)
    )
    return detection, score, cut


@pytest.fixture(scope="module")
def measured() -> dict[str, tuple[DetectionResult, ScoreReport, int]]:
    return {v: analyse(v) for v in VARIANTS}


# ---------------------------------------------------------------------------------------
# The controls — what must stay constant for the comparison to mean anything
# ---------------------------------------------------------------------------------------


def test_all_variants_have_the_same_crypto_call_count(measured) -> None:  # type: ignore[no-untyped-def]
    """The headline claim depends on this. If it drifts, the demo is comparing apples to
    oranges and act 4 becomes dishonest."""
    counts = {v: len(measured[v][0].crypto_calls) for v in VARIANTS}
    assert set(counts.values()) == {6}, counts


def test_f_sites_is_identical_across_variants(measured) -> None:  # type: ignore[no-untyped-def]
    """So any score movement is attributable to architecture, not to edit volume."""
    values = {measured[v][1].factors["call_sites"].normalised for v in VARIANTS}
    assert len(values) == 1, values


def test_all_variants_have_the_same_module_count(measured) -> None:  # type: ignore[no-untyped-def]
    files = {v: measured[v][0].files_scanned for v in VARIANTS}
    assert set(files.values()) == {14}, files


# ---------------------------------------------------------------------------------------
# The claim
# ---------------------------------------------------------------------------------------


def test_the_score_climbs_across_the_three_architectures(measured) -> None:  # type: ignore[no-untyped-def]
    scattered = measured[SCATTERED][1].agility_score
    facade = measured[FACADE][1].agility_score
    configured = measured[CONFIGURED][1].agility_score

    assert scattered < facade < configured, (scattered, facade, configured)
    assert configured > 2 * scattered, "the demo claims the score roughly doubles"


def test_the_facade_halves_the_minimum_node_cut(measured) -> None:
    """Act 4's centrepiece: six nodes must be removed, or three."""
    assert measured[SCATTERED][2] == 6
    assert measured[FACADE][2] == 3
    assert measured[CONFIGURED][2] == 3


def test_the_facade_confines_crypto_to_one_module(measured) -> None:  # type: ignore[no-untyped-def]
    def modules_with_crypto(variant: str) -> int:
        return len({s.module for s in measured[variant][0].crypto_calls})

    assert modules_with_crypto(SCATTERED) == 6
    assert modules_with_crypto(FACADE) == 1
    assert modules_with_crypto(CONFIGURED) == 1


def test_only_the_configured_variant_reads_its_algorithm_from_config(measured) -> None:  # type: ignore[no-untyped-def]
    assert measured[SCATTERED][0].config_reads == []
    assert measured[FACADE][0].config_reads == []
    assert measured[CONFIGURED][0].config_reads

    assert measured[CONFIGURED][1].factors["selection_source"].normalised == 1.0
    assert measured[SCATTERED][1].factors["selection_source"].normalised == 0.0


def test_each_jump_comes_from_the_factor_that_should_move(measured) -> None:
    """Isolation explains step one; algorithm selection explains step two.

    Asserted separately from the totals because "the number went up" is a weaker claim
    than "the number went up *for the stated reason*".
    """
    scattered, facade, configured = (measured[v][1].factors for v in VARIANTS)

    assert facade["isolation_layer"].normalised > scattered["isolation_layer"].normalised
    assert facade["selection_source"].normalised == scattered["selection_source"].normalised

    assert configured["isolation_layer"].normalised == facade["isolation_layer"].normalised
    assert configured["selection_source"].normalised > facade["selection_source"].normalised


def test_the_isolation_gain_is_modest_and_that_is_reported_honestly(measured) -> None:
    """A measured property of the metric, not a defect — and the demo says so.

    ``1 / (1 + cut)`` compresses hard: halving the cut from 6 to 3 is worth only about
    three points. The demo states this rather than implying the facade transforms the
    score, and this test pins the honest range so the narrative cannot drift from it.
    """
    gain = measured[FACADE][1].agility_score - measured[SCATTERED][1].agility_score
    assert 2.0 < gain < 6.0, f"narrative says ~3 points; measured {gain:.1f}"


def test_propagation_saturates_on_a_repository_this_size(measured) -> None:
    """Also stated in the demo as a known limit (glossary: propagation depth).

    ``1 - ancestors/modules`` clamps to 0 whenever a repository has more crypto-reaching
    scopes than modules, which is normal at this scale. It contributes nothing here, and
    pretending otherwise would misattribute the movement.
    """
    for variant in VARIANTS:
        assert measured[variant][1].factors["propagation_depth"].normalised == 0.0


# ---------------------------------------------------------------------------------------
# The recommendations that predicted the movement
# ---------------------------------------------------------------------------------------


def test_the_scattered_variant_recommends_exactly_the_refactors_we_then_apply(
    measured,  # type: ignore[no-untyped-def]
) -> None:
    """The strongest version of the claim: the tool asks for these two changes, we make
    them, and the score responds."""
    actions = " ".join(r.action for r in measured[SCATTERED][1].recommendations).lower()
    assert "facade" in actions
    assert "configuration" in actions


def test_the_configured_variant_no_longer_recommends_configuration(measured) -> None:  # type: ignore[no-untyped-def]
    factors = {r.factor for r in measured[CONFIGURED][1].deductions}
    assert "selection_source" not in factors
