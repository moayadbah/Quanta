"""Researcher-facing corpus workflow. No target code is executed by these commands."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Annotated

import typer

from quanta.bench.agreement import agreement
from quanta.bench.dataset import freeze
from quanta.bench.enumerate import enumerate_corpus
from quanta.bench.selection import select
from quanta.bench.worksheet import import_worksheet, worksheet
from quanta.core.ingest import _git_binary
from quanta.core.models import write_canonical_json
from quanta.errors import Reject

app = typer.Typer(
    help="Select, enumerate, independently label and freeze the research corpus.",
    no_args_is_help=True,
)
Root = Annotated[Path, typer.Option("--root", help="Benchmark directory.")]


def _error(exc: Reject) -> None:
    typer.echo(f"error: {exc.code}: {exc.detail}", err=True)
    raise typer.Exit(1)


@app.command("select")
def select_command(
    root: Root = Path("benchmark"), pages: Annotated[int, typer.Option(min=1, max=10)] = 10
) -> None:
    """Apply the documented query, stratification and candidate audit trail."""
    try:
        dataset = select(root, pages=pages)
    except Reject as exc:
        _error(exc)
        return
    typer.echo(f"Selected {len(dataset.repositories)} pinned repositories. The dataset is a draft.")


@app.command("enumerate")
def enumerate_command(
    corpus: Annotated[Path, typer.Option("--corpus")] = Path("benchmark/dataset.lock.json"),
) -> None:
    """Prepare the fixed list before either annotator starts classifying."""
    try:
        count = enumerate_corpus(corpus)
    except Reject as exc:
        _error(exc)
        return
    typer.echo(f"Enumerated {count} candidates.")


@app.command("worksheet")
def worksheet_command(
    annotator: Annotated[str, typer.Option("--annotator")],
    root: Root = Path("benchmark"),
) -> None:
    """Export blinded CSV worksheets for a1/a2, or disagreements for a3."""
    try:
        for path in worksheet(root, annotator):
            typer.echo(str(path))
    except Reject as exc:
        _error(exc)


@app.command("import")
def import_command(
    file: Annotated[Path, typer.Option("--worksheet")],
    annotator: Annotated[str, typer.Option("--annotator")],
    root: Root = Path("benchmark"),
) -> None:
    """Validate a completed worksheet and import its labels."""
    try:
        typer.echo(str(import_worksheet(root, file, annotator)))
    except Reject as exc:
        _error(exc)


@app.command("agree")
def agree_command(root: Root = Path("benchmark")) -> None:
    """Publish alpha, exact agreement and separate detector precision/recall."""
    try:
        report = agreement(root)
        write_canonical_json(root / "agreement.json", report)
    except Reject as exc:
        _error(exc)
        return
    typer.echo(str(root / "agreement.json"))


@app.command("freeze")
def freeze_command(root: Root = Path("benchmark")) -> None:
    """Validate the completed dataset, commit its manifest, and create dataset-v1.

    Commit candidate files, completed annotations and selection logs first. The command
    requires a clean worktree and an unused tag so it cannot commit unrelated changes.
    """
    try:
        status = subprocess.run(
            [_git_binary(), "-C", str(root), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        tag = subprocess.run(
            [
                _git_binary(),
                "-C",
                str(root),
                "show-ref",
                "--verify",
                "--quiet",
                "refs/tags/dataset-v1",
            ],
            capture_output=True,
            timeout=10,
        )
        if status.stdout.strip() or tag.returncode == 0:
            raise Reject(
                "BENCHMARK_INVALID",
                "commit inputs first; worktree must be clean and dataset-v1 unused",
            )
        freeze(root)
        subprocess.run(
            [_git_binary(), "-C", str(root), "add", "--", "dataset.lock.json", "agreement.json"],
            check=True,
            capture_output=True,
            timeout=10,
        )
        subprocess.run(
            [
                _git_binary(),
                "-C",
                str(root),
                "commit",
                "-m",
                "Freeze independently labelled benchmark v1",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        subprocess.run(
            [_git_binary(), "-C", str(root), "tag", "dataset-v1"],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except Reject as exc:
        _error(exc)
        return
    except (OSError, subprocess.SubprocessError) as exc:
        typer.echo(
            f"Git freeze step failed ({type(exc).__name__}); "
            "inspect the local manifest and git status.",
            err=True,
        )
        raise typer.Exit(1) from None
    typer.echo("Dataset frozen and tagged dataset-v1. Nothing was pushed.")
