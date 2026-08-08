"""Quanta command line (§9.3).

Only ``analyze`` is implemented at this milestone. The remaining subcommands — ``bench``,
``rewrite``, ``verify``, ``stats``, ``pr``, ``serve``, ``worker`` — belong to build order
steps 8 onward and are deliberately absent rather than stubbed: a command that exists but
does nothing is worse than one that is honestly missing.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

from quanta.config import Settings, get_settings
from quanta.core.analyze import (
    AnalysisOutcome,
    ProgressFn,
    analyze_path,
    analyze_repository,
    write_artifacts,
)
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
) -> None:
    """Analyse a repository and write cdg.json, score.json, meta.json and report.html."""
    settings = get_settings()

    if cbom is not None:
        # PROC-06 is a real requirement, but it belongs with the benchmark work that
        # measures scanner recall against the labels. Refusing is honest; silently
        # ignoring the flag would let someone believe their CBOM had been merged.
        _echo(
            "error: --cbom is not implemented yet (PROC-06 lands with the benchmark phase)",
            err=True,
        )
        raise typer.Exit(code=2)

    def progress(step: StepRecord) -> None:
        if step.status == "running":
            _echo(f"  .. {step.title}", err=True)
        elif step.status == "done":
            _echo(f"  ok {step.title}: {step.summary}", err=True)
        else:
            _echo(f"  !! {step.title}: {step.summary}", err=True)

    try:
        outcome = _run(target, settings, progress)
    except Reject as exc:
        # A stable machine code, never a traceback (§5.2.4).
        _echo(f"error: {exc.code}: {exc.detail}", err=True)
        raise typer.Exit(code=1) from None
    except Truncated as exc:
        _echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from None
    except QuantaError as exc:
        _echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    paths = write_artifacts(outcome, out)

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


def _run(target: str, settings: Settings, progress: ProgressFn) -> AnalysisOutcome:
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
        return analyze_path(local.resolve(), provenance, settings, progress)
    return analyze_repository(target, settings, progress)


def _summarise(outcome: AnalysisOutcome, paths: dict[str, Path]) -> None:
    score = outcome.score
    _echo("")
    _echo(f"  {score.provenance.repo} @ {score.provenance.commit_sha[:12]}")
    _echo(f"  Agility Score: {score.agility_score:.1f} / 100")
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
        f"{len(outcome.detection.crypto_calls)} crypto sites"
    )
    _echo("")
    for name in ("cdg", "score", "meta", "report"):
        _echo(f"  wrote {paths[name]}")


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

    root = artifacts or (Path.home() / ".quanta" / "artifacts")
    _echo(f"  Quanta {__version__}  ruleset {CRYPTO_RULESET_VERSION}")
    _echo(f"  artifacts -> {root}")
    _echo(f"  serving   -> http://{host}:{port}")
    _echo("  static analysis only; no repository code is ever executed")
    _echo("")

    uvicorn.run(create_app(root), host=host, port=port, log_level="warning")


if __name__ == "__main__":  # pragma: no cover
    app()
