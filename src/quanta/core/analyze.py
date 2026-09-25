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
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

import networkx as nx

from quanta.config import Settings, get_settings
from quanta.core.cbom import CbomImport, merge_cbom
from quanta.core.coverage import cover
from quanta.core.detect import DetectionResult, detect_repository
from quanta.core.fixes import FixFile, FixPlan, propose_repository
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
from quanta.core.metric_v2 import FORMULAS, coverage_from
from quanta.core.models import (
    AnalysisMeta,
    CryptoSite,
    Provenance,
    ScoreReport,
    StepEvidence,
    StepRecord,
    StepStatus,
    write_canonical_json,
)
from quanta.core.readiness import Readiness, assess, classify, classify_all
from quanta.core.report import render_report, write_report
from quanta.core.score import compute_score
from quanta.version import CRYPTO_RULESET_VERSION, METRIC_VERSION, analyzer_version

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

#: ``on_event(kind, payload)``: findings and proposals as they are produced, so a viewer
#: can inspect each one (and disagree with it) before any summary exists. Kinds:
#: ``parse_progress``, ``findings`` (one file's sites), ``proposals`` (one file's changes).
EventFn = Callable[[str, dict[str, object]], None]

#: Bound on the source text shown next to a finding. The line is display evidence only;
#: it is rendered as text, never as markup, and never re-parsed.
_SNIPPET_LIMIT = 240


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
    fixes: FixPlan = field(default_factory=FixPlan)
    findings: list[dict[str, object]] = field(default_factory=list)
    readiness: Readiness | None = None

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
        # Size 0 means GitHub's API did not answer (rate limit) and git resolved the commit.
        _ev("Size", f"{meta.size_kb:,} KB of {limit:,} KB limit", ok=meta.size_kb <= limit)
        if meta.size_kb
        else _ev("Size", "not reported; resolved over git, bounded by the clone budgets"),
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
    by_role: dict[str, int] = {}
    for site in detection.crypto_calls:
        by_role[site.role] = by_role.get(site.role, 0) + 1
    ratio = detection.coverage_ratio
    matched, unmatched = detection.api_matched, detection.api_unmatched
    evidence = [
        _ev("Execution", "parsed only, never imported, never executed", ok=True),
        _ev("Files parsed", f"{detection.files_scanned:,} ({detection.source_files:,} shipped)"),
        _ev(
            "Read, not parsed",
            f"{detection.files_text_only:,} test or docs files that name no crypto library",
        ),
        *(
            [
                _ev(
                    "Time limit",
                    f"{detection.files_unread:,} files not reached "
                    f"({detection.source_unread:,} shipped); shipped code was read first",
                    ok=False,
                )
            ]
            if detection.files_unread
            else []
        ),
        _ev("Crypto sites", len(detection.crypto_calls)),
        _ev(
            "Sites by file role",
            ", ".join(f"{k} {v}" for k, v in sorted(by_role.items())) or "none",
        ),
        _ev("Algorithm literals", len(detection.algo_literals)),
        _ev("Configuration reads", len(detection.config_reads)),
        _ev(
            "Crypto library calls recognised",
            f"{matched} of {matched + unmatched}" + ("" if ratio is None else f" ({ratio:.0%})"),
            ok=None if ratio is None else ratio >= 0.60,
        ),
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


#: The published normalisation for each factor (Master Plan 8.3 to 8.6), shown so a viewer
#: can check the arithmetic rather than trust it.
FACTOR_FORMULAS = FORMULAS


def _score_summary(score: ScoreReport) -> str:
    if score.status == "scored" and score.agility_score is not None:
        return f"Agility Score {score.agility_score:.1f} / 100"
    if score.status == "no_crypto_detected":
        return "No score: no cryptography detected in shipped code (not a 100)"
    code = score.refusal.code if score.refusal else "REFUSED"
    return f"No score: {code}"


def _score_evidence(score: ScoreReport) -> list[StepEvidence]:
    evidence = [
        _ev(
            "Metric",
            f"{score.provenance.metric_version}, weights {score.provenance.weights_version}",
            ok=True,
        ),
    ]
    if score.refusal is not None:
        evidence.append(_ev("Refused", f"{score.refusal.code}: {score.refusal.message}", ok=False))
    for key, factor in score.factors.items():
        evidence.append(
            _ev(
                key,
                f"raw {factor.raw} -> {FACTOR_FORMULAS[key]} -> {factor.normalised:.2f}"
                f" x {factor.weight:.2f} = {factor.contribution:.2f}",
            )
        )
    evidence.append(_ev("Result", _score_summary(score)))
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


def _snippet(root: Path, rel: str, line: int, cache: dict[str, list[str]]) -> str:
    if rel not in cache:
        try:
            cache[rel] = (root / rel).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            cache[rel] = []
    lines = cache[rel]
    text = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    return text if len(text) <= _SNIPPET_LIMIT else text[: _SNIPPET_LIMIT - 1] + "…"


def finding_payload(site: CryptoSite, snippet: str) -> dict[str, object]:
    """The public shape of one finding, as streamed and as stored in ``findings.json``."""
    return {
        "id": site.site_id,
        "file": site.file,
        "line": site.line,
        "kind": site.kind,
        "name": site.qualified_name,
        "algorithm": site.algorithm,
        "algorithms": list(site.algorithms),
        "category": site.category,
        "role": site.role,
        "form": site.form,
        "selection": site.selection,
        "free": site.free,
        "scored": site.scored,
        "weak": site.weak,
        "quantum_vulnerable": site.quantum_vulnerable,
        "parent": site.parent_site_id,
        "snippet": snippet,
        "readiness": classify(site).model_dump(mode="json"),
    }


def proposal_payload(file: FixFile) -> dict[str, object]:
    return {
        "path": file.path,
        "changes": [
            c.model_dump(exclude={"start", "end", "import_module", "import_name", "import_alias"})
            for c in file.changes
        ],
    }


def analyze_path(
    root: Path,
    provenance: Provenance,
    settings: Settings | None = None,
    progress: ProgressFn | None = None,
    tracer: Tracer | None = None,
    cbom: CbomImport | None = None,
    on_event: EventFn | None = None,
    parse_deadline: float | None = None,
) -> AnalysisOutcome:
    """Analyse an already-materialised source tree.

    Split out from :func:`analyze_repository` so the pipeline can be exercised against a
    local directory with no network, which is what the corpus runs and the tests do.
    """
    cfg = settings or get_settings()
    # Walked paths come back absolute; a relative root would not contain them.
    root = root.resolve()
    provenance = provenance.model_copy(
        update={
            "metric_version": METRIC_VERSION,
            "weights_version": cfg.weights.version,
            "cbom_sha256": cbom.sha256 if cbom is not None else None,
        }
    )
    trace = tracer or Tracer(progress)
    emit = on_event or (lambda _kind, _payload: None)
    snippets: dict[str, list[str]] = {}
    findings: list[dict[str, object]] = []
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
    last_report = [0.0]

    def on_file(index: int, total: int, one: DetectionResult) -> None:
        shown = [s for s in one.sites if s.kind == "crypto_call" or s.free]
        if shown:
            batch = [finding_payload(s, _snippet(root, s.file, s.line, snippets)) for s in shown]
            findings.extend(batch)
            emit("findings", {"file": shown[0].file, "items": batch})
        now = time.monotonic()
        if now - last_report[0] >= 0.5 or index == total:
            last_report[0] = now
            emit("parse_progress", {"done": index, "total": total})

    budget = parse_deadline or time.monotonic() + cfg.analysis.max_job_seconds * 0.6
    detection = detect_repository(walk.files, root, cfg, on_file=on_file, deadline=budget)
    if cbom is not None:
        merge_cbom(detection, cbom)
    # Repository-level findings (a package that implements a scheme itself) exist only
    # once every file is read; they join the list and the stream here.
    listed = {str(f["id"]) for f in findings}
    late: dict[str, list[dict[str, object]]] = {}
    for site in detection.sites:
        if (site.kind == "crypto_call" or site.free) and site.site_id not in listed:
            late.setdefault(site.file, []).append(
                finding_payload(site, _snippet(root, site.file, site.line, snippets))
            )
    for file, batch in sorted(late.items()):
        findings.extend(batch)
        emit("findings", {"file": file, "items": batch})
    timings["parsing"] = int((time.monotonic() - mark) * 1000)
    trace.finish(
        "parse",
        f"{len(detection.crypto_calls)} cryptographic site"
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
    coverage = coverage_from(detection, truncated=walk.truncated or detection.files_unread > 0)
    score = compute_score(detection, graph, provenance, coverage, cfg)
    timings["scoring"] = int((time.monotonic() - mark) * 1000)
    trace.finish(
        "score",
        _score_summary(score),
        _score_evidence(score),
    )

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
    readiness = assess(
        detection.sites,
        files_scanned=detection.files_scanned,
        source_unread=detection.source_unread,
    )
    # Findings streamed per file carry a provisional class; the stored ones carry the final
    # class, which can see a hybrid built across two sites of one module.
    final = classify_all(detection.sites)
    for finding in findings:
        site_class = final.get(str(finding["id"]))
        if site_class is not None:
            finding["readiness"] = site_class.model_dump(mode="json")
    fixes = propose_repository(
        root,
        walk.files,
        cfg.product,
        on_file=lambda f: emit("proposals", proposal_payload(f)),
    )
    # Every finding that needs action ends as a patch, a refusal or a guided migration.
    fixes = cover(fixes, findings)
    findings.sort(key=lambda f: (str(f["file"]), int(str(f["line"])), str(f["id"])))
    report_html = render_report(
        score, graph, meta, cfg, readiness=readiness, findings=findings, fixes=fixes
    )
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
        score=score,
        graph=graph,
        meta=meta,
        detection=detection,
        report_html=report_html,
        fixes=fixes,
        readiness=readiness,
        findings=findings,
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
    on_event: EventFn | None = None,
) -> AnalysisOutcome:
    """Analyse a public GitHub repository, pinned to its resolved commit SHA.

    Validation happens strictly before any network call, metadata resolution strictly
    before any clone, and the clone is removed unconditionally at exit.
    """
    cfg = settings or get_settings()
    job_started = time.monotonic()
    trace = Tracer(progress)

    trace.start("validate")
    owner, name = parse_repo_url(repo_url, cfg)  # no network yet — this is the SSRF control
    trace.finish(
        "validate",
        f"{owner}/{name} accepted, with no network call made",
        _validation_evidence(owner, name, cfg),
    )

    trace.start("resolve")
    if metadata is None:
        metadata = resolve_metadata(owner, name, cfg)
        # A renamed or transferred repository resolves to its new, re-validated name.
        owner, name = metadata.owner, metadata.name
    elif (metadata.owner, metadata.name) != (owner, name):
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
        metric_version=METRIC_VERSION,
        weights_version=cfg.weights.version,
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
        outcome = analyze_path(
            clone_root,
            provenance,
            cfg,
            progress,
            tracer=trace,
            cbom=cbom,
            on_event=on_event,
            # The job limit counts from the start, clone included; parsing gets 70% of it
            # so the graph, proposals and report still finish inside it.
            parse_deadline=job_started + cfg.analysis.max_job_seconds * 0.7,
        )

    # scratch_dir has now removed the tree, unconditionally (INGEST-09).
    trace.start("cleanup")
    trace.finish(
        "cleanup",
        "working copy deleted",
        [
            _ev("Clone directory", "removed", ok=True),
            _ev("Source retained", "only bounded files with reviewable fix proposals", ok=True),
            _ev("Applies to", "success, failure and timeout paths alike", ok=True),
        ],
    )

    # replace(), not a field-by-field copy: a new outcome field can never be dropped here.
    return replace(outcome, meta=outcome.meta.model_copy(update={"steps": tuple(trace.steps)}))


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
    write_canonical_json(out_dir / "fixes.json", outcome.fixes)
    write_canonical_json(out_dir / "findings.json", {"version": 1, "findings": outcome.findings})
    if outcome.readiness is not None:
        write_canonical_json(out_dir / "readiness.json", outcome.readiness)
    return paths
