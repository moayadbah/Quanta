"""The analysis pipeline: ingest → detect → CDG → score → render.

One function, shared by the CLI today and by the worker's analyzer child later, so the web
tier and the offline corpus runs cannot drift apart (§4.3: ``quanta.core`` is imported by
both planes).

The clone is deleted unconditionally, on every path including failure and timeout
(INGEST-09). That is what :func:`~quanta.core.ingest.scratch_dir` guarantees, and it is
why acquisition happens inside a context manager rather than in a ``try``/``finally`` the
next refactor might unbalance.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import networkx as nx

from quanta.config import Settings, get_settings
from quanta.core.detect import DetectionResult, detect_repository
from quanta.core.graph import build_cdg, to_node_link
from quanta.core.ingest import (
    RepoMetadata,
    clone_pinned,
    parse_repo_url,
    resolve_metadata,
    scratch_dir,
    walk_repository,
)
from quanta.core.models import (
    AnalysisMeta,
    Coverage,
    Provenance,
    ScoreReport,
    write_canonical_json,
)
from quanta.core.report import render_report, write_report
from quanta.core.score import compute_score
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version

#: Phases, in order. The worker writes one ``job_events`` row per phase transition.
PHASES = ("cloning", "walking", "parsing", "graph", "scoring", "rendering")

ProgressFn = Callable[[str, int, int], None]


@dataclass
class AnalysisOutcome:
    score: ScoreReport
    graph: nx.DiGraph
    meta: AnalysisMeta
    detection: DetectionResult
    report_html: str


def _noop(phase: str, done: int, total: int) -> None:
    return None


def analyze_path(
    root: Path,
    provenance: Provenance,
    settings: Settings | None = None,
    progress: ProgressFn | None = None,
) -> AnalysisOutcome:
    """Analyse an already-materialised source tree.

    Split out from :func:`analyze_repository` so the pipeline can be exercised against a
    local directory with no network — which is what the corpus runs and the tests do.
    """
    cfg = settings or get_settings()
    emit = progress or _noop
    started = datetime.now(UTC)
    timings: dict[str, int] = {}

    def _phase(name: str, index: int) -> float:
        emit(name, index, len(PHASES))
        return time.monotonic()

    mark = _phase("walking", 1)
    walk = walk_repository(root, cfg)
    timings["walking"] = int((time.monotonic() - mark) * 1000)

    mark = _phase("parsing", 2)
    detection = detect_repository(walk.files, root, cfg)
    timings["parsing"] = int((time.monotonic() - mark) * 1000)

    mark = _phase("graph", 3)
    graph = build_cdg(detection)
    timings["graph"] = int((time.monotonic() - mark) * 1000)

    mark = _phase("scoring", 4)
    coverage = Coverage(
        files_scanned=detection.files_scanned,
        files_unparseable=len(detection.unparseable),
        truncated=walk.truncated,
    )
    score = compute_score(detection, graph, provenance, coverage, cfg)
    timings["scoring"] = int((time.monotonic() - mark) * 1000)

    finished = datetime.now(UTC)
    meta = AnalysisMeta(
        provenance=provenance,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        duration_ms=int((finished - started).total_seconds() * 1000),
        phase_durations_ms=timings,
        # Only the first declared truncation is surfaced here; the report names the budget
        # that was hit, which is the actionable part.
        truncation=walk.truncations[0] if walk.truncations else None,
        unparseable=tuple(detection.unparseable),
        files_scanned=detection.files_scanned,
        sites_detected=len(detection.crypto_calls),
    )

    mark = _phase("rendering", 5)
    report_html = render_report(score, graph, meta, cfg)
    timings["rendering"] = int((time.monotonic() - mark) * 1000)

    return AnalysisOutcome(
        score=score, graph=graph, meta=meta, detection=detection, report_html=report_html
    )


def analyze_repository(
    repo_url: str,
    settings: Settings | None = None,
    progress: ProgressFn | None = None,
) -> AnalysisOutcome:
    """Analyse a public GitHub repository, pinned to its resolved commit SHA.

    Validation happens strictly before any network call, metadata resolution strictly
    before any clone, and the clone is removed unconditionally at exit.
    """
    cfg = settings or get_settings()
    emit = progress or _noop

    owner, name = parse_repo_url(repo_url, cfg)  # no network yet — this is the SSRF control
    metadata: RepoMetadata = resolve_metadata(owner, name, cfg)

    provenance = Provenance(
        repo=metadata.slug,
        commit_sha=metadata.commit_sha,
        analyzer_version=analyzer_version(),
        crypto_ruleset_version=CRYPTO_RULESET_VERSION,
    )

    with scratch_dir() as scratch:
        clone_root = scratch / "repo"
        emit("cloning", 0, len(PHASES))
        clone_pinned(owner, name, metadata.commit_sha, clone_root, cfg)
        return analyze_path(clone_root, provenance, cfg, progress)


def write_artifacts(outcome: AnalysisOutcome, out_dir: Path) -> dict[str, Path]:
    """Write the four artifacts (§5.1.3) and return their paths.

    ``cdg.json`` and ``score.json`` are canonical: sorted keys, quantised floats, no
    timestamps. Timings live in ``meta.json`` alone, which is what lets NFR-03 hold.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "cdg": out_dir / "cdg.json",
        "score": out_dir / "score.json",
        "meta": out_dir / "meta.json",
        "report": out_dir / "report.html",
    }
    write_canonical_json(paths["cdg"], to_node_link(outcome.graph))
    write_canonical_json(paths["score"], outcome.score)
    write_canonical_json(paths["meta"], outcome.meta)
    write_report(paths["report"], outcome.report_html)
    return paths
