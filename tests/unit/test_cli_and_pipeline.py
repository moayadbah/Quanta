"""End-to-end pipeline and CLI (§11.4 first milestone, DoD-C1…C5).

Everything here runs against a local tree, so the suite needs no network. The
network-backed path is exercised by ``quanta analyze <url>`` and is verified separately;
what these tests pin down is that the pipeline produces the four artifacts, that the two
canonical ones are byte-identical across runs, and that the report opens standalone.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from quanta.cli import app
from quanta.core.analyze import analyze_path, write_artifacts
from quanta.core.graph import from_node_link
from quanta.core.models import Provenance
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"
runner = CliRunner()


def _provenance() -> Provenance:
    return Provenance(
        repo="owner/name",
        commit_sha="a" * 40,
        analyzer_version=analyzer_version(),
        crypto_ruleset_version=CRYPTO_RULESET_VERSION,
    )


# ---------------------------------------------------------------------------------------
# Artifacts (§5.1.3)
# ---------------------------------------------------------------------------------------


def test_pipeline_writes_all_four_artifacts(tmp_path: Path) -> None:
    outcome = analyze_path(FIXTURES / "hardcoded_crypto", _provenance())
    paths = write_artifacts(outcome, tmp_path / "out")

    for name in ("cdg", "score", "meta", "report"):
        assert paths[name].is_file(), f"{name} not written"
        assert paths[name].stat().st_size > 0


def test_cdg_json_round_trips_from_disk(tmp_path: Path) -> None:
    """DoD-C3."""
    outcome = analyze_path(FIXTURES / "facade_crypto", _provenance())
    paths = write_artifacts(outcome, tmp_path / "out")

    data = json.loads(paths["cdg"].read_text())
    restored = from_node_link(data)
    assert restored.number_of_nodes() == outcome.graph.number_of_nodes()
    assert restored.number_of_edges() == outcome.graph.number_of_edges()


def test_score_json_matches_the_published_schema(tmp_path: Path) -> None:
    outcome = analyze_path(FIXTURES / "hardcoded_crypto", _provenance())
    paths = write_artifacts(outcome, tmp_path / "out")
    score = json.loads(paths["score"].read_text())

    assert score["schema_version"] == "1.0"
    assert set(score["provenance"]) == {
        "repo",
        "commit_sha",
        "analyzer_version",
        "crypto_ruleset_version",
    }
    assert set(score["factors"]) == {
        "call_sites",
        "isolation_layer",
        "selection_source",
        "propagation_depth",
    }
    for factor in score["factors"].values():
        assert set(factor) == {"raw", "normalised", "weight", "contribution"}
    for deduction in score["deductions"]:
        assert set(deduction) == {"factor", "points", "reason", "citations"}
        assert deduction["citations"]
    assert set(score["coverage"]) == {"files_scanned", "files_unparseable", "truncated"}


def test_canonical_artifacts_are_byte_identical_across_runs(tmp_path: Path) -> None:
    """NFR-03 / DoD-C3 — three runs, byte-for-byte."""
    digests: dict[str, set[bytes]] = {"cdg": set(), "score": set()}
    for i in range(3):
        outcome = analyze_path(FIXTURES / "hardcoded_crypto", _provenance())
        paths = write_artifacts(outcome, tmp_path / f"run{i}")
        for name in digests:
            digests[name].add(paths[name].read_bytes())

    assert len(digests["cdg"]) == 1
    assert len(digests["score"]) == 1


def test_timings_live_only_in_meta(tmp_path: Path) -> None:
    """A duration inside score.json would break determinism on the very next run."""
    outcome = analyze_path(FIXTURES / "hardcoded_crypto", _provenance())
    paths = write_artifacts(outcome, tmp_path / "out")

    score_text = paths["score"].read_text()
    assert "duration" not in score_text
    assert "started_at" not in score_text

    meta = json.loads(paths["meta"].read_text())
    assert "duration_ms" in meta
    assert "phase_durations_ms" in meta


def test_report_opens_standalone(tmp_path: Path) -> None:
    """DoD-C5 / NFR-07: no network, no server, inline SVG."""
    outcome = analyze_path(FIXTURES / "facade_crypto", _provenance())
    paths = write_artifacts(outcome, tmp_path / "out")

    html = paths["report"].read_text()
    assert "<svg" in html, "the CDG figure must be inline SVG"
    assert "<style>" in html, "CSS must be inline"
    assert "<link" not in html.lower()
    assert "https://" not in html


def test_truncation_is_declared_in_meta_and_coverage(tmp_path: Path) -> None:
    from quanta.config import Settings

    root = tmp_path / "repo"
    root.mkdir()
    for i in range(30):
        (root / f"m{i:03d}.py").write_text("import hashlib\nhashlib.sha1(b'')\n")

    settings = Settings()
    settings.ingest.max_files = 10
    outcome = analyze_path(root, _provenance(), settings)

    assert outcome.score.coverage.truncated is True
    assert outcome.meta.truncation is not None
    assert outcome.meta.truncation.reason == "max_files"
    assert "truncation" in outcome.report_html.lower()


# ---------------------------------------------------------------------------------------
# CLI surface (§9.3)
# ---------------------------------------------------------------------------------------


def test_analyze_local_directory(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["analyze", str(FIXTURES / "hardcoded_crypto"), "--out", str(tmp_path / "out")]
    )
    assert result.exit_code == 0, result.output
    assert "Agility Score" in result.output
    assert (tmp_path / "out" / "report.html").is_file()


def test_analyze_json_output_is_valid_score_json(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["analyze", str(FIXTURES / "hardcoded_crypto"), "--out", str(tmp_path / "out"), "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "1.0"
    assert 0.0 <= payload["agility_score"] <= 100.0


def test_malformed_url_reports_a_stable_error_code_not_a_traceback(tmp_path: Path) -> None:
    """§5.2.4: clients get a stable machine code; tracebacks are never serialised."""
    result = runner.invoke(app, ["analyze", "https://evil.com/o/r", "--out", str(tmp_path)])
    assert result.exit_code == 1
    assert "HOST_NOT_ALLOWED" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://github.com/o/r", "HOST_NOT_ALLOWED"),
        ("https://github.com/o/r/extra", "URL_MALFORMED"),
        ("https://127.0.0.1/o/r", "HOST_NOT_ALLOWED"),
    ],
)
def test_hostile_urls_are_refused_by_the_cli(url: str, code: str, tmp_path: Path) -> None:
    result = runner.invoke(app, ["analyze", url, "--out", str(tmp_path)])
    assert result.exit_code == 1
    assert code in result.output


def test_cbom_flag_refuses_rather_than_silently_ignoring(tmp_path: Path) -> None:
    """Accepting a flag that does nothing would let someone believe their CBOM was merged."""
    cbom = tmp_path / "cbom.json"
    cbom.write_text("{}")
    result = runner.invoke(
        app,
        [
            "analyze",
            str(FIXTURES / "no_crypto"),
            "--out",
            str(tmp_path / "out"),
            "--cbom",
            str(cbom),
        ],
    )
    assert result.exit_code == 2
    assert "not implemented" in result.output


def test_version_reports_the_provenance_components() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert CRYPTO_RULESET_VERSION in result.output
    assert analyzer_version() in result.output
