"""§9.4 — static assertion: no shell, no dynamic evaluation anywhere in ``src/quanta``.

These are §11.2 hard prohibitions, so they are enforced mechanically rather than by review.
The checks parse our own source with the standard-library ``ast`` module: a substring grep
would trip over ``re.compile`` and over the word "shell" in prose, and would miss
``getattr(os, "system")``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "quanta"

#: Builtins that turn data into code. None of them has a legitimate use in this codebase.
FORBIDDEN_BUILTINS = {"eval", "exec", "compile", "__import__"}

#: Module-level functions that hand a string to a shell.
FORBIDDEN_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
    ("commands", "getoutput"),
}


def _python_files() -> list[Path]:
    files = sorted(SRC.rglob("*.py"))
    assert files, "no source files found — the test is looking in the wrong place"
    return files


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _location(path: Path, node: ast.AST) -> str:
    return f"{path.relative_to(SRC.parent.parent)}:{getattr(node, 'lineno', '?')}"


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: p.name)
def test_no_shell_true(path: Path) -> None:
    """``shell=True`` is prohibited anywhere, for any reason (§11.2)."""
    offenders = [
        _location(path, node)
        for node in ast.walk(_parse(path))
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
    ]
    assert not offenders, f"shell=True found at {offenders}"


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: p.name)
def test_no_dynamic_evaluation(path: Path) -> None:
    offenders = [
        f"{_location(path, node)} ({node.func.id})"
        for node in ast.walk(_parse(path))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in FORBIDDEN_BUILTINS
    ]
    assert not offenders, f"dynamic evaluation found at {offenders}"


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: p.name)
def test_no_shell_helpers(path: Path) -> None:
    offenders = []
    for node in ast.walk(_parse(path)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        value = node.func.value
        if isinstance(value, ast.Name) and (value.id, node.func.attr) in FORBIDDEN_CALLS:
            offenders.append(f"{_location(path, node)} ({value.id}.{node.func.attr})")
    assert not offenders, f"shell helper found at {offenders}"


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: p.name)
def test_no_os_system_import(path: Path) -> None:
    """``from os import system`` would evade the attribute-call check above."""
    offenders = []
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.ImportFrom) and node.module in {"os", "subprocess", "commands"}:
            for alias in node.names:
                if alias.name in {"system", "popen", "getoutput", "getstatusoutput"}:
                    offenders.append(f"{_location(path, node)} ({node.module}.{alias.name})")
    assert not offenders, f"shell helper imported at {offenders}"


def test_the_checker_would_actually_catch_a_violation(tmp_path: Path) -> None:
    """A green static check is worthless if the checker is broken. Prove it bites."""
    bad = tmp_path / "bad.py"
    bad.write_text("import subprocess\nsubprocess.run('ls', shell=True)\neval('1')\n")
    tree = ast.parse(bad.read_text())

    shell_hits = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        for kw in n.keywords
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
    ]
    eval_hits = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id in FORBIDDEN_BUILTINS
    ]
    assert shell_hits and eval_hits
