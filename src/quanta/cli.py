"""Quanta command line (§9.3).

Analysis, corpus preparation, statistics and the local service are available.
Migration and verification require an independently annotated, frozen benchmark.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from quanta.bench.cli import app as bench_app
from quanta.config import Settings, get_settings
from quanta.core.analyze import (
    AnalysisOutcome,
    ProgressFn,
    analyze_path,
    analyze_repository,
    write_artifacts,
)
from quanta.core.cbom import CbomImport, read_cbom
from quanta.core.models import Provenance, StepRecord, dump_canonical_json
from quanta.errors import QuantaError, Reject, Truncated
from quanta.version import CRYPTO_RULESET_VERSION, __version__, analyzer_version

app = typer.Typer(
    name="quanta",
    help="Cryptographic agility measurement for Python repositories.",
    no_args_is_help=True,
    add_completion=False,
)


def _echo(message: str, *, err: bool = False) -> None:
    typer.echo(message, err=err)


def _subprocess_detail(exc: BaseException) -> str:
    """The stderr of whichever subprocess caused ``exc``, for ``--trace`` only.

    Codes like ``CLONE_FAILED`` are deliberately opaque, because the text underneath is
    written by the repository being analysed and the web tier must never echo it back. On
    a developer's own terminal, behind an explicit flag, that trade-off inverts: without
    this, a clone that fails for a local reason — no git, a proxy, a missing DLL — is
    indistinguishable from one that fails for any other.
    """
    cause = exc.__cause__
    stderr = getattr(cause, "stderr", None)
    if not stderr:
        return "  (no subprocess output was captured)"
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
    lines = [line for line in stderr.strip().splitlines() if line.strip()]
    return "\n".join(f"  git: {line}" for line in lines[-10:])


@app.command()
def version() -> None:
    """Print the analyzer and crypto ruleset versions."""
    _echo(f"quanta {__version__}")
    _echo(f"crypto ruleset {CRYPTO_RULESET_VERSION}")
    _echo(f"provenance analyzer_version {analyzer_version()}")


@app.command()
def analyze(
    target: Annotated[
        str,
        typer.Argument(
            help="Public GitHub repository URL, or a path to a local source tree.",
            metavar="URL|PATH",
        ),
    ],
    out: Annotated[Path, typer.Option("--out", help="Directory to write artifacts into.")] = Path(
        "./out"
    ),
    cbom: Annotated[
        Path | None,
        typer.Option("--cbom", help="Optional CycloneDX 1.6 CBOM to merge as a site source."),
    ] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Print score.json to stdout instead of a summary.")
    ] = False,
    trace: Annotated[
        bool,
        typer.Option("--trace", help="Print the full pipeline trace with per-step evidence."),
    ] = False,
    pdf: Annotated[
        bool, typer.Option("--pdf", help="Also write report.pdf, the readiness report as a PDF.")
    ] = False,
) -> None:
    """Analyse a repository and write its readiness, findings, changes and report."""
    settings = get_settings()

    def progress(step: StepRecord) -> None:
        if step.status == "running":
            _echo(f"  .. {step.title}", err=True)
        elif step.status == "done":
            _echo(f"  ok {step.title}: {step.summary}", err=True)
        else:
            _echo(f"  !! {step.title}: {step.summary}", err=True)

    try:
        outcome = _run(target, settings, progress, read_cbom(cbom) if cbom else None)
    except Reject as exc:
        # A stable machine code, never a traceback (§5.2.4).
        _echo(f"error: {exc.code}: {exc.detail}", err=True)
        if trace:
            _echo(_subprocess_detail(exc), err=True)
        raise typer.Exit(code=1) from None
    except Truncated as exc:
        _echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from None
    except QuantaError as exc:
        _echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    paths = write_artifacts(outcome, out)
    if pdf:
        paths["pdf"] = _write_pdf(out)

    if as_json:
        sys.stdout.write(dump_canonical_json(outcome.score))
        return

    if trace:
        _print_trace(outcome)
    _summarise(outcome, paths)


def _print_trace(outcome: AnalysisOutcome) -> None:
    """Print the same evidence the web UI shows, so the two never diverge."""
    _echo("")
    _echo("  Pipeline trace")
    for step in outcome.steps:
        mark = {"done": "ok", "failed": "!!", "skipped": "--"}.get(step.status, "..")
        _echo(f"    {mark} {step.title}  ({step.duration_ms} ms)")
        if step.summary:
            _echo(f"       {step.summary}")
        for item in step.evidence:
            flag = "" if item.ok is None else ("  [ok]" if item.ok else "  [!]")
            _echo(f"         - {item.label}: {item.value}{flag}")


def _write_pdf(out: Path) -> Path:
    """The same PDF the web product exports, built from the artifacts just written."""
    from quanta.core.fixes import FixPlan
    from quanta.core.pdf import render_pdf
    from quanta.core.report_data import build

    def read(name: str) -> Any:
        path = out / name
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    data = build(
        score=read("score.json") or {},
        meta=read("meta.json") or {},
        readiness=read("readiness.json"),
        findings=(read("findings.json") or {}).get("findings", []),
        fixes=FixPlan.model_validate(read("fixes.json") or {}).public(),
    )
    target = out / "report.pdf"
    target.write_bytes(render_pdf(data))
    return target


def _run(
    target: str,
    settings: Settings,
    progress: ProgressFn,
    cbom: CbomImport | None = None,
) -> AnalysisOutcome:
    """Dispatch on whether the target is a local directory or a repository URL.

    A local tree has no commit to pin to, so its provenance records an all-zero SHA. That
    is a deliberate marker: such an artifact is reproducible only relative to a working
    copy, and must never be mistaken for a pinned corpus result.
    """
    local = Path(target)
    if local.is_dir():
        provenance = Provenance(
            repo=f"local:{local.resolve().name}",
            commit_sha="0" * 40,
            analyzer_version=analyzer_version(),
            crypto_ruleset_version=CRYPTO_RULESET_VERSION,
        )
        return analyze_path(local.resolve(), provenance, settings, progress, cbom=cbom)
    return analyze_repository(target, settings, progress, cbom=cbom)


def _summarise(outcome: AnalysisOutcome, paths: dict[str, Path]) -> None:
    score = outcome.score
    _echo("")
    _echo(f"  {score.provenance.repo} @ {score.provenance.commit_sha[:12]}")
    if score.agility_score is not None:
        _echo(
            f"  Agility Score: {score.agility_score:.1f} / 100 ({score.provenance.metric_version})"
        )
    elif score.refusal is not None:
        _echo(f"  No score: {score.refusal.code}. {score.refusal.message}")
    else:
        _echo("  No score: no cryptography detected in shipped code (this is not a 100).")
    _echo("")

    for key, factor in score.factors.items():
        weighted = f"{factor.normalised:>5.2f} x {factor.weight:.2f} = {factor.contribution:>5.2f}"
        _echo(f"    {key:<20} {weighted}")

    if score.deductions:
        _echo("")
        _echo("  Deductions:")
        for deduction in score.deductions:
            _echo(f"    -{deduction.points:5.2f}  {deduction.reason}")
            for citation in list(deduction.citations)[:3]:
                _echo(f"            {citation}")

    if outcome.meta.truncation:
        _echo("")
        _echo(f"  ! declared truncation: {outcome.meta.truncation.reason}")

    _echo("")
    _echo(
        f"  {score.coverage.files_scanned} files scanned, "
        f"{score.coverage.files_unparseable} unparseable, "
        f"{len(outcome.detection.crypto_calls)} crypto sites, "
        f"{score.coverage.crypto_api_calls_matched} of "
        f"{score.coverage.crypto_api_calls_matched + score.coverage.crypto_api_calls_unmatched}"
        " crypto library calls recognised"
    )
    _echo("")
    for name in ("cdg", "score", "meta", "report"):
        _echo(f"  wrote {paths[name]}")
    _echo(f"  wrote {paths['score'].parent / 'fixes.json'}")
    _echo(f"  wrote {paths['score'].parent / 'findings.json'}")
    if (paths["score"].parent / "readiness.json").is_file():
        _echo(f"  wrote {paths['score'].parent / 'readiness.json'}")
    if "pdf" in paths:
        _echo(f"  wrote {paths['pdf']}")


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host", help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port.")] = 8000,
    artifacts: Annotated[
        Path | None, typer.Option("--artifacts", help="Where analysis artifacts are written.")
    ] = None,
) -> None:
    """Serve the web UI and API on localhost (§9.3).

    Binds to 127.0.0.1 by default. ADR-014 fixes deployment at local only — a public URL
    would add abuse handling, TLS, rate-limit tuning and a permanent liability for a
    demonstration a laptop already satisfies.
    """
    import uvicorn

    from quanta.web.app import create_app

    settings = get_settings()
    root = artifacts or settings.artifact_root
    _echo(f"  Quanta {__version__}  ruleset {CRYPTO_RULESET_VERSION}")
    _echo(f"  artifacts -> {root}")
    _echo(f"  serving   -> http://{host}:{port}")
    _echo("  static analysis only; no repository code is ever executed")
    _echo("")

    uvicorn.run(create_app(root, settings.db), host=host, port=port, log_level="warning")


@app.command()
def worker(
    worker_id: Annotated[str, typer.Option("--id", help="Unique worker instance name.")] = "w1",
) -> None:
    """Process durable analysis jobs independently of the API."""
    from quanta.web.worker import run_worker

    try:
        run_worker(worker_id)
    except KeyboardInterrupt:
        return


def _worker_entry(worker_id: str) -> None:
    from quanta.web.worker import run_worker

    try:
        run_worker(worker_id)
    except KeyboardInterrupt:
        return


@app.command()
def up(
    port: Annotated[int, typer.Option("--port", help="Bind port.")] = 8000,
) -> None:
    """Run the whole local product with one command: the web app and one worker.

    The worker is a separate process (analysis never runs in the API). Verification with
    a project's own tests is ``quanta verify``; the web product offers it only when
    QUANTA_VERIFY__WEB=true. Stop both with Ctrl+C.
    """
    import multiprocessing as mp

    import uvicorn

    from quanta.web.app import create_app

    settings = get_settings()
    process = mp.get_context("spawn").Process(target=_worker_entry, args=("local-1",))
    process.start()
    _echo(f"  Quanta {__version__}  ruleset {CRYPTO_RULESET_VERSION}")
    _echo(f"  data      -> {settings.db.parent}")
    _echo(f"  worker    -> pid {process.pid}")
    _echo(f"  open      -> http://127.0.0.1:{port}")
    _echo("  analysis never runs repository code")
    _echo("")
    try:
        uvicorn.run(
            create_app(settings.artifact_root, settings.db),
            host="127.0.0.1",
            port=port,
            log_level="warning",
        )
    finally:
        process.terminate()
        process.join(timeout=5)


def _local_outcome(path: Path) -> AnalysisOutcome:
    settings = get_settings()
    provenance = Provenance(
        repo=f"local:{path.resolve().name}",
        commit_sha="0" * 40,
        analyzer_version=analyzer_version(),
        crypto_ruleset_version=CRYPTO_RULESET_VERSION,
    )
    return analyze_path(path.resolve(), provenance, settings)


@app.command()
def trace(
    path: Annotated[Path, typer.Argument(help="Local source tree with a test suite.")],
    out: Annotated[Path, typer.Option("--out", help="Where to write trace.json.")] = Path(
        "./out-trace"
    ),
) -> None:
    """Check the static inventory against what the project's own tests execute.

    Installs the project in a Docker container (network only during install), runs its
    tests once with no network and a crypto-call tracer, and reports how many of the
    executed algorithm-bearing lines static analysis found (Master Plan 25).
    """
    from quanta.core.graph import to_node_link
    from quanta.verify.pipeline import trace_check
    from quanta.verify.sandbox import docker_available

    if not path.is_dir():
        _echo("error: PATH must be a local directory", err=True)
        raise typer.Exit(1)
    if not docker_available():
        _echo("error: SANDBOX_UNAVAILABLE: Docker is required to run repository tests", err=True)
        raise typer.Exit(1)
    outcome = _local_outcome(path)
    write_artifacts(outcome, out)
    report = trace_check(path, to_node_link(outcome.graph), out, path.resolve().name)
    if report.get("status") != "done":
        _echo(f"  unverifiable: {report.get('reason')}")
        raise typer.Exit(1)
    executed, found = report["executed_a_lines"], report["found_by_static"]
    _echo(f"  tests: {report['tests']['passed']} passed, {report['tests']['failed']} failed")
    _echo(f"  the tests ran {executed} algorithm-bearing crypto lines in shipped code")
    _echo(f"  the static inventory had found {found} of them")
    for miss in report["missed"][:10]:
        _echo(f"    missed {miss['file']}:{miss['line']}  {', '.join(miss['callees'])}")
    if report["too_few_to_judge"]:
        _echo(f"  {report['note']}")
    _echo(f"  wrote {out / 'trace.json'}")


@app.command()
def verify(
    path: Annotated[Path, typer.Argument(help="Local source tree with a test suite.")],
    select: Annotated[
        str, typer.Option("--select", help="Comma-separated fix ids, or 'all'.")
    ] = "all",
    out: Annotated[Path, typer.Option("--out", help="Where to write verification.json.")] = Path(
        "./out-verify"
    ),
) -> None:
    """Verify proposed fixes with the project's own tests (Master Plan 10.10).

    Runs the tests twice before and twice after the selected changes, with no network,
    checks which changed lines ran, and swaps the algorithm at each changed site to test
    whether the tests can see the change. Prints one verdict.
    """
    from quanta.core.fixes import review
    from quanta.verify.pipeline import verify_changes
    from quanta.verify.sandbox import docker_available

    if not path.is_dir():
        _echo("error: PATH must be a local directory", err=True)
        raise typer.Exit(1)
    if not docker_available():
        _echo("error: SANDBOX_UNAVAILABLE: Docker is required to run repository tests", err=True)
        raise typer.Exit(1)
    outcome = _local_outcome(path)
    ids = [c.id for f in outcome.fixes.files for c in f.changes]
    chosen = ids if select == "all" else [s.strip() for s in select.split(",") if s.strip()]
    if not chosen:
        _echo("  no fix proposals to verify")
        for skipped in outcome.fixes.skipped:
            _echo(f"    refused {skipped.path}:{skipped.line} {skipped.code}")
        return
    try:
        result = review(outcome.fixes, chosen)
    except Reject as exc:
        _echo(f"error: {exc.code}: {exc.detail}", err=True)
        raise typer.Exit(1) from None
    files = [{"path": f["path"], "content": f["content"]} for f in result["files"]]
    verdict = verify_changes(path, files, out, path.resolve().name)
    _echo(f"  verdict: {verdict.verdict}")
    for reason in verdict.reasons:
        _echo(f"    {reason}")
    _echo(f"  wrote {out / 'verification.json'}")


app.add_typer(bench_app, name="bench")


@app.command("stats")
def stats_command(
    command: Annotated[
        str, typer.Argument(help="mcnemar, bootstrap, sensitivity, collinearity, all")
    ],
    data: Annotated[Path, typer.Option("--data")] = Path("benchmark/results.jsonl"),
    scores: Annotated[Path, typer.Option("--scores")] = Path("benchmark/scores"),
    out: Annotated[Path, typer.Option("--out")] = Path("benchmark/statistics"),
) -> None:
    """Compute reproducible statistics from actual score and engine result files."""
    from quanta.stats.analysis import run_statistics

    try:
        for path in run_statistics(command, data, scores, out):
            _echo(str(path))
    except Reject as exc:
        _echo(f"error: {exc.code}: {exc.detail}", err=True)
        raise typer.Exit(1) from None


if __name__ == "__main__":  # pragma: no cover
    app()
