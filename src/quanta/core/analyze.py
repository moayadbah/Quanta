"""The analysis pipeline: validate → resolve → clone → walk → parse → graph → score → render.

One module, shared by the CLI and the web tier, so the two planes cannot drift apart
(§4.3: ``quanta.core`` is imported by both).

Every step emits a :class:`~quanta.core.models.StepRecord` carrying the *evidence* for
what it did — which controls ran, what they refused, what they measured. Two reasons that
matters beyond the demo:

* The score has been traceable since PROC-08, but the pipeline has not. A reviewer asking
  "what exactly did it check before it made a network call?" deserves a machine-readable
  answer, not a phase name.
* The strongest claims in this project are negative ones — nothing is executed, symlinks
  are never followed, ambiguous callees are never guessed. A negative claim is invisible
  unless the thing that did not happen is counted.

The clone is deleted unconditionally, on every path including failure and timeout
(INGEST-09), which is why acquisition happens inside a context manager rather than a
``try``/``finally`` that a later refactor might unbalance.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import networkx as nx

from quanta.config import Settings, get_settings
from quanta.core.cbom import CbomImport, merge_cbom
from quanta.core.detect import DetectionResult, detect_repository
from quanta.core.graph import ResolutionStats, build_cdg, to_node_link
from quanta.core.ingest import (
    RepoMetadata,
    WalkResult,
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
    StepEvidence,
    StepRecord,
    StepStatus,
    write_canonical_json,
)
from quanta.core.report import render_report, write_report
from quanta.core.score import compute_score
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version

#: The pipeline, in order. Ids are stable and are what the UI keys on.
STEP_TITLES: tuple[tuple[str, str], ...] = (
    ("validate", "Validate the URL"),
    ("resolve", "Resolve repository metadata"),
    ("clone", "Clone at a pinned commit"),
    ("walk", "Walk the source tree"),
    ("parse", "Parse and detect crypto"),
    ("graph", "Build the dependency graph"),
    ("score", "Compute the Agility Score"),
    ("render", "Render artifacts"),
    ("cleanup", "Delete the working copy"),
)

#: Legacy phase names retained for ``meta.phase_durations_ms`` continuity.
PHASES = ("cloning", "walking", "parsing", "graph", "scoring", "rendering")

ProgressFn = Callable[[StepRecord], None]


@dataclass
class Tracer:
    """Accumulates :class:`StepRecord`\\ s and streams them as they change.

    Each step is emitted twice — once ``running`` so a viewer sees it start, once
    terminal with its evidence attached.
    """

    progress: ProgressFn | None = None
    steps: list[StepRecord] = field(default_factory=list)
    _started: float = 0.0

    def _emit(self, record: StepRecord) -> None:
        if self.progress is not None:
            self.progress(record)

    def start(self, step_id: str) -> None:
        title = dict(STEP_TITLES)[step_id]
        self._started = time.monotonic()
        record = StepRecord(id=step_id, title=title, status="running")
        self.steps.append(record)
        self._emit(record)

    def finish(
        self,
        step_id: str,
        summary: str,
        evidence: list[StepEvidence] | None = None,
        status: StepStatus = "done",
    ) -> None:
        title = dict(STEP_TITLES)[step_id]
        record = StepRecord(
            id=step_id,
            title=title,
            status=status,
            summary=summary,
            evidence=tuple(evidence or ()),
            duration_ms=int((time.monotonic() - self._started) * 1000),
        )
        # Replace the "running" placeholder rather than appending beside it.
        for i, existing in enumerate(self.steps):
            if existing.id == step_id:
                self.steps[i] = record
                break
        else:
            self.steps.append(record)
        self._emit(record)

    def fail(self, step_id: str, summary: str) -> None:
        self.finish(step_id, summary, status="failed")


def _ev(label: str, value: object, ok: bool | None = None) -> StepEvidence:
    return StepEvidence(label=label, value=str(value), ok=ok)


@dataclass
class AnalysisOutcome:
    score: ScoreReport
    graph: nx.DiGraph
    meta: AnalysisMeta
    detection: DetectionResult
    report_html: str

    @property
    def steps(self) -> tuple[StepRecord, ...]:
        return self.meta.steps


# ---------------------------------------------------------------------------------------
# Evidence builders — one per step, kept separate so the pipeline reads as a pipeline
# ---------------------------------------------------------------------------------------


def _validation_evidence(owner: str, name: str, settings: Settings) -> list[StepEvidence]:
    """The SSRF control set (§7.3 T1), every check stated as having held.

    The caption that matters is the last one: none of this required a network call. An
    implementation that resolved the host first would give the same verdict while having
    already leaked a DNS lookup to an attacker-chosen name.
    """
    return [
        _ev("Scheme", "https", ok=True),
        _ev("Host allowlist", ", ".join(settings.ingest.allowed_hosts), ok=True),
        _ev("Userinfo / port / query", "none present", ok=True),
        _ev("Owner", owner, ok=True),
        _ev("Repository", name, ok=True),
        _ev("Character class", "[A-Za-z0-9._-]{1,100}", ok=True),
        _ev("Network calls so far", "0 — validation precedes DNS", ok=True),
    ]


def _metadata_evidence(meta: RepoMetadata, settings: Settings) -> list[StepEvidence]:
    limit = settings.ingest.max_repo_kb
    return [
        _ev("Visibility", "public", ok=True),
        _ev("Default branch", meta.default_branch),
        _ev("Size", f"{meta.size_kb:,} KB of {limit:,} KB limit", ok=meta.size_kb <= limit),
        _ev("Head commit", meta.commit_sha),
        _ev("Analysis pinned to", meta.commit_sha[:12], ok=True),
    ]


def _clone_evidence(settings: Settings, sha: str) -> list[StepEvidence]:
    return [
        _ev("Depth", "1 — no history, so no committer personal data", ok=True),
        _ev("Submodules", "refused — attacker-controlled URLs are an SSRF vector", ok=True),
        _ev("Hooks", "core.hooksPath points at a directory that never exists", ok=True),
        _ev("Shell", "shell=False, argument vector only", ok=True),
        _ev("Timeout", f"{settings.ingest.clone_timeout_s}s"),
        _ev("Checked-out HEAD", f"{sha[:12]} matches resolved SHA", ok=True),
    ]


def _walk_evidence(walk: WalkResult, settings: Settings) -> list[StepEvidence]:
    cfg = settings.ingest
    evidence = [
        _ev("Python files considered", f"{walk.files_considered:,}"),
        _ev("Accepted for analysis", f"{len(walk.files):,}"),
        _ev("Symlinks skipped", f"{walk.symlinks_skipped:,}", ok=True),
        _ev("Directories pruned", f"{walk.dirs_pruned:,} (denylist, symlinks)"),
        _ev("Total bytes", f"{walk.total_bytes:,} of {cfg.max_total_bytes:,}"),
        _ev("Containment", "every path re-checked under the clone root", ok=True),
    ]
    for record in walk.truncations:
        evidence.append(
            _ev(
                f"Declared truncation: {record.reason}",
                f"limit {record.limit:,}, observed {record.observed:,}",
                ok=False,
            )
        )
    if not walk.truncations:
        evidence.append(_ev("Budgets", "none exceeded", ok=True))
    return evidence


def _parse_evidence(detection: DetectionResult) -> list[StepEvidence]:
    evidence = [
        _ev("Execution", "parsed only — never imported, never executed", ok=True),
        _ev("Files parsed", f"{detection.files_scanned:,}"),
        _ev("Crypto call sites", len(detection.crypto_calls)),
        _ev("Algorithm literals", len(detection.algo_literals)),
        _ev("Configuration reads", len(detection.config_reads)),
        _ev("Ruleset version", CRYPTO_RULESET_VERSION),
    ]
    weak = [s for s in detection.sites if s.weak]
    quantum = [s for s in detection.crypto_calls if s.quantum_vulnerable]
    if weak:
        evidence.append(_ev("Weak primitives", f"{len(weak)} (MD5/SHA1/3DES/RC4)", ok=False))
    if quantum:
        evidence.append(_ev("Quantum-vulnerable", f"{len(quantum)} sites", ok=False))
    if detection.unparseable:
        shown = ", ".join(f"{u.file} ({u.reason})" for u in detection.unparseable[:3])
        evidence.append(
            _ev("Unparseable", f"{len(detection.unparseable)} — listed, not dropped: {shown}")
        )
    return evidence


def _graph_evidence(graph: nx.DiGraph, stats: ResolutionStats) -> list[StepEvidence]:
    kinds: dict[str, int] = {}
    for _n, data in graph.nodes(data=True):
        kinds[str(data.get("kind"))] = kinds.get(str(data.get("kind")), 0) + 1
    edges: dict[str, int] = {}
    low = 0
    for _s, _t, data in graph.edges(data=True):
        edges[str(data.get("kind"))] = edges.get(str(data.get("kind")), 0) + 1
        if data.get("confidence") == "low":
            low += 1

    kind_breakdown = ", ".join(f"{k} {v}" for k, v in sorted(kinds.items()))
    edge_breakdown = ", ".join(f"{k} {v}" for k, v in sorted(edges.items()))

    return [
        _ev("Nodes", f"{graph.number_of_nodes():,} — {kind_breakdown}"),
        _ev("Edges", f"{graph.number_of_edges():,} — {edge_breakdown}"),
        _ev("Low-confidence edges", f"{low} (every 'call' edge, by rule)", ok=True),
        _ev("Callees resolved", f"{stats.callees_resolved:,} of {stats.callees_seen:,}"),
        _ev(
            "Callees dropped, not guessed",
            f"{stats.callees_ambiguous:,} ambiguous, {stats.callees_unresolved:,} unresolvable",
            ok=True,
        ),
        _ev("Imports", f"{stats.imports_resolved:,} internal, {stats.imports_external:,} external"),
    ]


#: The published normalisation for each factor (§5.3.3), shown so a viewer can check the
#: arithmetic rather than trust it.
FACTOR_FORMULAS = {
    "call_sites": "1 / (1 + log10(1 + n))",
    "isolation_layer": "1 / (1 + minimum node cut)",
    "selection_source": "config reads / (config reads + literals)",
    "propagation_depth": "1 - (ancestors / modules), clamped",
}


def _score_evidence(score: ScoreReport) -> list[StepEvidence]:
    evidence = [
        _ev("Weights", "weights-v1, pre-registered and git-tagged", ok=True),
    ]
    for key, factor in score.factors.items():
        evidence.append(
            _ev(
                key,
                f"raw {factor.raw} -> {FACTOR_FORMULAS[key]} -> {factor.normalised:.2f}"
                f" x {factor.weight:.2f} = {factor.contribution:.2f}",
            )
        )
    evidence.append(_ev("Agility Score", f"{score.agility_score:.1f} / 100"))
    for deduction in score.deductions:
        evidence.append(
            _ev(
                f"-{deduction.points:.2f} {deduction.factor}",
                f"{deduction.reason} [{', '.join(list(deduction.citations)[:3])}]",
                ok=False,
            )
        )
    return evidence


# ---------------------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------------------


def analyze_path(
    root: Path,
    provenance: Provenance,
    settings: Settings | None = None,
    progress: ProgressFn | None = None,
    tracer: Tracer | None = None,
    cbom: CbomImport | None = None,
) -> AnalysisOutcome:
    """Analyse an already-materialised source tree.

    Split out from :func:`analyze_repository` so the pipeline can be exercised against a
    local directory with no network — which is what the corpus runs and the tests do.
    """
    cfg = settings or get_settings()
    if cbom is not None:
        provenance = provenance.model_copy(
            update={
                "analyzer_version": f"{provenance.analyzer_version}+cbom.{cbom.sha256}",
            }
        )
    trace = tracer or Tracer(progress)
    started = datetime.now(UTC)
    timings: dict[str, int] = {}

    trace.start("walk")
    mark = time.monotonic()
    walk = walk_repository(root, cfg)
    timings["walking"] = int((time.monotonic() - mark) * 1000)
    trace.finish(
        "walk",
        f"{len(walk.files):,} Python files accepted"
        + (f", {walk.symlinks_skipped} symlink(s) skipped" if walk.symlinks_skipped else ""),
        _walk_evidence(walk, cfg),
    )

    trace.start("parse")
    mark = time.monotonic()
    detection = detect_repository(walk.files, root, cfg)
    if cbom is not None:
        merge_cbom(detection, cbom)
    timings["parsing"] = int((time.monotonic() - mark) * 1000)
    trace.finish(
        "parse",
        f"{len(detection.crypto_calls)} cryptographic call site"
        f"{'' if len(detection.crypto_calls) == 1 else 's'} detected",
        _parse_evidence(detection),
    )

    trace.start("graph")
    mark = time.monotonic()
    stats = ResolutionStats()
    graph = build_cdg(detection, stats)
    timings["graph"] = int((time.monotonic() - mark) * 1000)
    trace.finish(
        "graph",
        f"{graph.number_of_nodes():,} nodes, {graph.number_of_edges():,} edges",
        _graph_evidence(graph, stats),
    )

    trace.start("score")
    mark = time.monotonic()
    coverage = Coverage(
        files_scanned=detection.files_scanned,
        files_unparseable=len(detection.unparseable),
        truncated=walk.truncated,
    )
    score = compute_score(detection, graph, provenance, coverage, cfg)
    timings["scoring"] = int((time.monotonic() - mark) * 1000)
    trace.finish("score", f"Agility Score {score.agility_score:.1f} / 100", _score_evidence(score))

    finished = datetime.now(UTC)

    trace.start("render")
    mark = time.monotonic()
    meta = AnalysisMeta(
        provenance=provenance,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        duration_ms=int((finished - started).total_seconds() * 1000),
        phase_durations_ms=timings,
        truncation=walk.truncations[0] if walk.truncations else None,
        truncations=tuple(walk.truncations),
        cbom_sha256=cbom.sha256 if cbom else None,
        cbom_unlocated=cbom.unlocated if cbom else 0,
        unparseable=tuple(detection.unparseable),
        files_scanned=detection.files_scanned,
        sites_detected=len(detection.crypto_calls),
        steps=tuple(trace.steps),
    )
    report_html = render_report(score, graph, meta, cfg)
    timings["rendering"] = int((time.monotonic() - mark) * 1000)
    trace.finish(
        "render",
        "report.html rendered, self-contained",
        [
            _ev("Report size", f"{len(report_html):,} bytes"),
            _ev("External requests", "0 — inline SVG and inline CSS", ok=True),
            _ev("Opens from", "file:// with no server and no network", ok=True),
            _ev("Artifacts", "cdg.json, score.json, meta.json, report.html"),
        ],
    )

    # Re-attach the trace so meta.json carries the render step too.
    meta = meta.model_copy(update={"steps": tuple(trace.steps)})

    return AnalysisOutcome(
        score=score, graph=graph, meta=meta, detection=detection, report_html=report_html
    )


def analyze_repository(
    repo_url: str,
    settings: Settings | None = None,
    progress: ProgressFn | None = None,
    *,
    metadata: RepoMetadata | None = None,
    scratch_parent: Path | None = None,
    after_clone: Callable[[], None] | None = None,
    cbom: CbomImport | None = None,
) -> AnalysisOutcome:
    """Analyse a public GitHub repository, pinned to its resolved commit SHA.

    Validation happens strictly before any network call, metadata resolution strictly
    before any clone, and the clone is removed unconditionally at exit.
    """
    cfg = settings or get_settings()
    trace = Tracer(progress)

    trace.start("validate")
    owner, name = parse_repo_url(repo_url, cfg)  # no network yet — this is the SSRF control
    trace.finish(
        "validate",
        f"{owner}/{name} accepted, with no network call made",
        _validation_evidence(owner, name, cfg),
    )

    trace.start("resolve")
    metadata = metadata or resolve_metadata(owner, name, cfg)
    if (metadata.owner, metadata.name) != (owner, name):
        from quanta.errors import Reject

        raise Reject("SHA_MISMATCH", "metadata does not match repository")
    trace.finish(
        "resolve",
        f"public, {metadata.size_kb:,} KB, pinned to {metadata.commit_sha[:12]}",
        _metadata_evidence(metadata, cfg),
    )

    provenance = Provenance(
        repo=metadata.slug,
        commit_sha=metadata.commit_sha,
        analyzer_version=analyzer_version(),
        crypto_ruleset_version=CRYPTO_RULESET_VERSION,
    )

    with scratch_dir(parent=scratch_parent) as scratch:
        clone_root = scratch / "repo"
        trace.start("clone")
        mark = time.monotonic()
        clone_pinned(owner, name, metadata.commit_sha, clone_root, cfg)
        clone_ms = int((time.monotonic() - mark) * 1000)
        trace.finish(
            "clone",
            f"shallow clone at {metadata.commit_sha[:12]} in {clone_ms} ms",
            _clone_evidence(cfg, metadata.commit_sha),
        )

        if after_clone is not None:
            after_clone()
        outcome = analyze_path(clone_root, provenance, cfg, progress, tracer=trace, cbom=cbom)

    # scratch_dir has now removed the tree, unconditionally (INGEST-09).
    trace.start("cleanup")
    trace.finish(
        "cleanup",
        "working copy deleted",
        [
            _ev("Clone directory", "removed", ok=True),
            _ev("Source retained", "none — nothing untrusted is kept", ok=True),
            _ev("Applies to", "success, failure and timeout paths alike", ok=True),
        ],
    )

    return AnalysisOutcome(
        score=outcome.score,
        graph=outcome.graph,
        meta=outcome.meta.model_copy(update={"steps": tuple(trace.steps)}),
        detection=outcome.detection,
        report_html=outcome.report_html,
    )


def write_artifacts(outcome: AnalysisOutcome, out_dir: Path) -> dict[str, Path]:
    """Write the four artifacts (§5.1.3) and return their paths.

    ``cdg.json`` and ``score.json`` are canonical: sorted keys, quantised floats, no
    timestamps. Timings and the trace live in ``meta.json`` alone, which is what lets
    NFR-03 hold.
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
