"""§9.4 — static assertion: ``core/`` never imports or executes target code.

This is the load-bearing claim of the whole architecture (§1.5, ADR-001). The Analysis
Plane is cheap to secure *only* because the arbitrary-code-execution class is removed by
design. If a future change quietly adds an ``importlib.import_module`` on a target
module's name, every isolation argument in the design collapses — and nothing else in the
test suite would notice.

``subprocess`` is permitted in ``core/`` for exactly one purpose: invoking ``git`` to
clone. Any other executable is a violation.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[2] / "src" / "quanta" / "core"
WEB = Path(__file__).resolve().parents[2] / "src" / "quanta" / "web"

#: Modules whose entire purpose is to load and run code.
FORBIDDEN_MODULES = {
    "importlib",
    "runpy",
    "imp",
    "pip",
    "setuptools",
    "pkg_resources",
    "py_compile",
}


def _files(*roots: Path) -> list[Path]:
    return sorted(p for root in roots for p in root.rglob("*.py"))


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


@pytest.mark.parametrize("path", _files(CORE, WEB), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_no_code_loading_imports(path: Path) -> None:
    offenders = []
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Import):
            offenders += [
                f"{path.name}:{node.lineno} import {a.name}"
                for a in node.names
                if a.name.split(".")[0] in FORBIDDEN_MODULES
            ]
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.split(".")[0] in FORBIDDEN_MODULES
        ):
            offenders.append(f"{path.name}:{node.lineno} from {node.module}")
    assert not offenders, f"code-loading import in the Analysis Plane: {offenders}"


@pytest.mark.parametrize("path", _files(CORE, WEB), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_no_dunder_import_call(path: Path) -> None:
    offenders = [
        f"{path.name}:{n.lineno}"
        for n in ast.walk(_parse(path))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "__import__"
    ]
    assert not offenders, f"__import__ call in the Analysis Plane: {offenders}"


@pytest.mark.parametrize("path", _files(CORE, WEB), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_subprocess_only_ever_runs_git(path: Path) -> None:
    """The only external program the Analysis Plane may execute is git (§11.2)."""
    offenders = []
    for node in ast.walk(_parse(path)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_subprocess = (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
            and func.attr in {"run", "Popen", "call", "check_call", "check_output"}
        )
        if not is_subprocess or not node.args:
            continue

        argv = node.args[0]
        if not isinstance(argv, ast.List) or not argv.elts:
            offenders.append(f"{path.name}:{node.lineno} argv is not a literal list")
            continue

        # The executable is either a "git"-ish literal or the _git_binary() helper, whose
        # own resolution is asserted separately below.
        head = ast.unparse(argv.elts[0])
        if "git" not in head:
            offenders.append(f"{path.name}:{node.lineno} executes {head}")

    assert not offenders, f"non-git subprocess in the Analysis Plane: {offenders}"


@pytest.mark.parametrize("path", _files(CORE, WEB), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_no_subprocess_call_omits_an_argument_vector(path: Path) -> None:
    """A string first argument implies shell parsing even without shell=True on Windows."""
    for node in ast.walk(_parse(path)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.args
        ):
            assert not isinstance(node.args[0], ast.Constant), (
                f"{path.name}:{node.lineno} passes a string, not an argument vector"
            )


def test_git_binary_resolves_to_an_absolute_path() -> None:
    from quanta.core.ingest import _git_binary

    resolved = _git_binary()
    assert Path(resolved).is_absolute()
    assert Path(resolved).name in {"git", "git.exe"}


def test_the_checker_would_actually_catch_a_violation(tmp_path: Path) -> None:
    """Prove the subprocess check bites, so a green run means something."""
    bad = tmp_path / "bad.py"
    bad.write_text("import subprocess\nsubprocess.run(['pip', 'install', 'x'])\n")

    offenders = []
    for node in ast.walk(ast.parse(bad.read_text())):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.args
            and isinstance(node.args[0], ast.List)
            and "git" not in ast.unparse(node.args[0].elts[0])
        ):
            offenders.append(node.lineno)
    assert offenders, "the checker failed to flag a pip invocation"
