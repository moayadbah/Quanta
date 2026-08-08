"""§9.4 — T2 path traversal and symlink escape (INGEST-07).

The repository author controls every file name and link target in the tree, so traversal
is treated as hostile input. Asserted here: a synthetic repo containing an absolute-target
link, a relative escape, and a symlink cycle yields **zero files outside the root** and
**terminates**.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from quanta.core.ingest import walk_repository


@pytest.fixture
def hostile_repo(tmp_path: Path) -> Path:
    """A tree containing every symlink shape that matters."""
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)

    (root / "real.py").write_text("import hashlib\n")
    (root / "pkg" / "mod.py").write_text("x = 1\n")

    # 1. Absolute escape to a real, sensitive file.
    os.symlink("/etc/passwd", root / "passwd_link.py")
    # 2. Relative escape above the clone root.
    os.symlink("../../", root / "up_link")
    (tmp_path / "outside.py").write_text("SECRET = 1\n")
    os.symlink(tmp_path / "outside.py", root / "outside_link.py")
    # 3. A symlink cycle — a naive walker never terminates here.
    os.symlink(root / "loop_a", root / "loop_b")
    os.symlink(root / "loop_b", root / "loop_a")
    # 4. A directory symlink pointing back at an ancestor: the other cycle shape.
    os.symlink(root, root / "pkg" / "self_link")

    return root


def test_walk_terminates_and_stays_inside_the_root(hostile_repo: Path) -> None:
    result = walk_repository(hostile_repo)  # must not hang

    root = hostile_repo.resolve()
    for f in result.files:
        assert f.resolve().is_relative_to(root), f"escaped the clone root: {f}"


def test_no_symlink_is_ever_yielded(hostile_repo: Path) -> None:
    """Skipped unconditionally — files *and* directories (INGEST-07)."""
    result = walk_repository(hostile_repo)
    for f in result.files:
        assert not f.is_symlink()


def test_sensitive_targets_are_not_reachable(hostile_repo: Path) -> None:
    result = walk_repository(hostile_repo)
    names = {f.name for f in result.files}
    assert "passwd_link.py" not in names
    assert "outside_link.py" not in names
    assert "outside.py" not in names


def test_real_files_are_still_collected(hostile_repo: Path) -> None:
    """The control must not be a blanket refusal — genuine sources still analyse."""
    result = walk_repository(hostile_repo)
    names = {f.name for f in result.files}
    assert names == {"real.py", "mod.py"}


def test_denylisted_directories_are_pruned(tmp_path: Path) -> None:
    """PROC-01: vendored and build trees are not the repository's own code."""
    root = tmp_path / "repo"
    for d in (".git", ".venv", "node_modules", "build", "site-packages", ".tox"):
        (root / d).mkdir(parents=True)
        (root / d / "vendored.py").write_text("x = 1\n")
    (root / "keep.py").write_text("x = 1\n")

    result = walk_repository(root)
    assert {f.name for f in result.files} == {"keep.py"}


def test_only_python_sources_are_collected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for name in ("a.py", "b.pyi", "c.txt", "d.md", "e.so", "f.pyc", "setup.cfg"):
        (root / name).write_text("x")

    result = walk_repository(root)
    assert {f.name for f in result.files} == {"a.py", "b.pyi"}


def test_traversal_order_is_deterministic(tmp_path: Path) -> None:
    """NFR-03: os.walk yields readdir order, which is not stable. We sort."""
    root = tmp_path / "repo"
    (root / "z" / "y").mkdir(parents=True)
    (root / "a").mkdir()
    for p in ("m.py", "a/b.py", "z/y/c.py", "z/d.py"):
        (root / p).write_text("x = 1\n")

    runs = [[str(f.relative_to(root)) for f in walk_repository(root).files] for _ in range(5)]
    assert all(r == runs[0] for r in runs)
    assert runs[0] == sorted(runs[0])
