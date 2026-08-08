"""The pipeline trace (ADR-022 support, and the NFR-03 regression guard).

The trace exists so the *pipeline* is auditable, not just the score. Its riskiest property
is where it lives: steps carry durations, and a duration inside ``cdg.json`` or
``score.json`` would break byte-identical reproducibility on the very next run. The
determinism tests here are therefore the load-bearing ones.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from quanta.core.analyze import STEP_TITLES, Tracer, analyze_path, write_artifacts
from quanta.core.detect import detect_repository
from quanta.core.graph import ResolutionStats, build_cdg
from quanta.core.ingest import walk_repository
from quanta.core.models import Provenance, StepEvidence, StepRecord
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"

PROVENANCE = Provenance(
    repo="owner/name",
    commit_sha="a" * 40,
    analyzer_version=analyzer_version(),
    crypto_ruleset_version=CRYPTO_RULESET_VERSION,
)


def run(name: str = "hardcoded_crypto"):  # type: ignore[no-untyped-def]
    return analyze_path(FIXTURES / name, PROVENANCE)


# ---------------------------------------------------------------------------------------
# Determinism — the reason placement matters
# ---------------------------------------------------------------------------------------


def test_trace_does_not_break_artifact_determinism(tmp_path: Path) -> None:
    """NFR-03 / DoD-C3, re-asserted after adding timing data to the pipeline."""
    payloads: dict[str, set[bytes]] = {"cdg": set(), "score": set()}
    for i in range(3):
        paths = write_artifacts(run(), tmp_path / f"run{i}")
        for key in payloads:
            payloads[key].add(paths[key].read_bytes())

    assert len(payloads["cdg"]) == 1
    assert len(payloads["score"]) == 1


def test_no_timing_leaks_into_the_canonical_artifacts(tmp_path: Path) -> None:
    paths = write_artifacts(run(), tmp_path / "out")
    for key in ("cdg", "score"):
        text = paths[key].read_text()
        for forbidden in ("duration_ms", "started_at", "finished_at", "steps"):
            assert forbidden not in text, f"{forbidden} must not appear in {key}.json"


def test_trace_is_written_to_meta(tmp_path: Path) -> None:
    paths = write_artifacts(run(), tmp_path / "out")
    meta = json.loads(paths["meta"].read_text())
    assert len(meta["steps"]) >= 1
    assert all({"id", "title", "status", "summary", "evidence"} <= set(s) for s in meta["steps"])


# ---------------------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------------------


def test_local_analysis_records_the_offline_steps() -> None:
    """A local path skips validate/resolve/clone/cleanup — those are network concerns."""
    steps = {s.id for s in run().steps}
    assert {"walk", "parse", "graph", "score", "render"} <= steps


def test_every_recorded_step_carries_evidence() -> None:
    for step in run().steps:
        assert step.status == "done"
        assert step.summary
        assert step.evidence, f"{step.id} recorded no evidence"


def test_parse_step_states_that_nothing_was_executed() -> None:
    """The project's headline claim (§1.5) must be in the machine-readable record."""
    parse = next(s for s in run().steps if s.id == "parse")
    execution = next(e for e in parse.evidence if e.label == "Execution")
    assert "never" in execution.value.lower()
    assert execution.ok is True


def test_walk_step_counts_what_it_refused(tmp_path: Path) -> None:
    """A negative claim is invisible unless the thing that did not happen is counted."""
    import os

    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "hook.py").write_text("x = 1\n")
    (root / "real.py").write_text("import hashlib\nhashlib.sha1(b'')\n")
    os.symlink("/etc/passwd", root / "link.py")

    walk = walk_repository(root)
    assert walk.symlinks_skipped == 1
    assert walk.dirs_pruned >= 1
    assert walk.files_considered >= 2
    assert {f.name for f in walk.files} == {"real.py"}


def test_graph_step_counts_callees_it_declined_to_guess() -> None:
    """§5.2.3 forbids guessing; RR-2 requires the shortfall be measured, not concealed."""
    detection = detect_repository(
        walk_repository(FIXTURES / "facade_crypto").files, FIXTURES / "facade_crypto"
    )
    stats = ResolutionStats()
    build_cdg(detection, stats)

    assert stats.callees_seen > 0
    assert stats.callees_resolved > 0
    assert stats.callees_seen == (
        stats.callees_resolved + stats.callees_ambiguous + stats.callees_unresolved
    )


def test_score_step_shows_the_arithmetic() -> None:
    """A viewer should be able to check the number, not just receive it."""
    score_step = next(s for s in run().steps if s.id == "score")
    rendered = " ".join(e.value for e in score_step.evidence)
    assert "log10" in rendered
    assert "raw" in rendered
    assert "->" in rendered


def test_deductions_appear_in_the_trace_with_citations() -> None:
    score_step = next(s for s in run().steps if s.id == "score")
    failures = [e for e in score_step.evidence if e.ok is False]
    assert failures
    assert any(".py:" in e.value for e in failures)


# ---------------------------------------------------------------------------------------
# Tracer mechanics
# ---------------------------------------------------------------------------------------


def test_tracer_emits_running_then_terminal() -> None:
    emitted: list[StepRecord] = []
    tracer = Tracer(progress=emitted.append)

    tracer.start("walk")
    tracer.finish("walk", "done it", [StepEvidence(label="a", value="b", ok=True)])

    assert [e.status for e in emitted] == ["running", "done"]
    assert len(tracer.steps) == 1, "the running placeholder must be replaced, not duplicated"
    assert tracer.steps[0].summary == "done it"


def test_tracer_records_failure() -> None:
    tracer = Tracer()
    tracer.start("clone")
    tracer.fail("clone", "it broke")
    assert tracer.steps[0].status == "failed"


def test_step_titles_are_unique_and_ordered() -> None:
    ids = [sid for sid, _ in STEP_TITLES]
    assert len(ids) == len(set(ids)) == 9
    assert ids[0] == "validate"
    assert ids[-1] == "cleanup"


@pytest.mark.parametrize("name", ["hardcoded_crypto", "configured_crypto", "no_crypto"])
def test_trace_is_produced_for_every_fixture(name: str) -> None:
    outcome = run(name)
    assert outcome.meta.steps
    assert all(s.status == "done" for s in outcome.meta.steps)
