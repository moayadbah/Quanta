"""§9.4 — T3 resource exhaustion (INGEST-08).

Each of the three fixture scenarios — many files, one oversized file, deep nesting — must
produce a **declared truncation record**, not an OOM and not a silent drop. The
distinction is the point: a partial corpus reported as complete would understate every
downstream number, and the report has no way to know.

The fast tests drive the budgets through configuration. One test at the literal §9.4 scale
(25 000 files) is marked ``slow`` so the real limit is exercised without making every CI
run pay for it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quanta.config import Settings
from quanta.core.ingest import safe_walk, walk_repository
from quanta.errors import Truncated


def _settings(**ingest: object) -> Settings:
    s = Settings()
    for k, v in ingest.items():
        setattr(s.ingest, k, v)
    return s


def _reasons(root: Path, settings: Settings) -> set[str]:
    return {t.reason for t in walk_repository(root, settings).truncations}


# ---------------------------------------------------------------------------------------
# File count
# ---------------------------------------------------------------------------------------


def test_file_count_budget_declares_truncation(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for i in range(60):
        (root / f"m{i:03d}.py").write_text("x = 1\n")

    settings = _settings(max_files=50)
    result = walk_repository(root, settings)

    assert result.truncated
    assert len(result.files) <= 50
    record = next(t for t in result.truncations if t.reason == "max_files")
    assert record.limit == 50
    assert record.observed > record.limit


def test_file_count_budget_raises_from_safe_walk(tmp_path: Path) -> None:
    """The §5.3.1 generator contract: files are yielded, *then* Truncated is raised."""
    root = tmp_path / "repo"
    root.mkdir()
    for i in range(60):
        (root / f"m{i:03d}.py").write_text("x = 1\n")

    settings = _settings(max_files=50)
    collected = []
    with pytest.raises(Truncated) as exc:
        for f in safe_walk(root, settings):
            collected.append(f)

    assert len(collected) == 50, "partial work must survive the truncation"
    assert exc.value.reason == "max_files"


# ---------------------------------------------------------------------------------------
# Oversized file
# ---------------------------------------------------------------------------------------


def test_oversized_file_is_declared_not_silently_dropped(tmp_path: Path) -> None:
    """§5.3.1's sketch `continue`s past this file. INGEST-08 requires it be declared."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "huge.py").write_text("# " + "a" * 5_000_000)
    (root / "small.py").write_text("x = 1\n")

    settings = _settings(max_file_bytes=2_000_000)
    result = walk_repository(root, settings)

    assert {f.name for f in result.files} == {"small.py"}
    assert result.truncated, "an oversized file must not vanish silently"
    record = next(t for t in result.truncations if t.reason == "max_file_bytes")
    assert record.limit == 2_000_000
    assert record.observed > 2_000_000


def test_total_bytes_budget_declares_truncation(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for i in range(10):
        (root / f"m{i}.py").write_text("x" * 1000)

    settings = _settings(max_total_bytes=3000, max_file_bytes=2_000_000)
    result = walk_repository(root, settings)

    assert result.truncated
    assert result.total_bytes <= 3000
    assert "max_total_bytes" in {t.reason for t in result.truncations}


# ---------------------------------------------------------------------------------------
# Depth
# ---------------------------------------------------------------------------------------


def test_deep_nesting_declares_truncation(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    deep = root
    for i in range(50):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / "buried.py").write_text("x = 1\n")
    (root / "top.py").write_text("x = 1\n")

    settings = _settings(max_depth=40)
    result = walk_repository(root, settings)

    assert "max_depth" in _reasons(root, settings)
    assert "top.py" in {f.name for f in result.files}
    assert "buried.py" not in {f.name for f in result.files}


def test_deep_nesting_terminates_without_recursion_error(tmp_path: Path) -> None:
    """os.walk is iterative; this guards against a future recursive rewrite."""
    root = tmp_path / "repo"
    deep = root
    for i in range(200):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / "x.py").write_text("x = 1\n")

    walk_repository(root, _settings(max_depth=40))  # must simply return


# ---------------------------------------------------------------------------------------
# A clean repository declares nothing
# ---------------------------------------------------------------------------------------


def test_normal_repository_is_not_marked_truncated(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for i in range(5):
        (root / f"m{i}.py").write_text("x = 1\n")

    result = walk_repository(root)
    assert not result.truncated
    assert result.truncations == []
    assert len(result.files) == 5


# ---------------------------------------------------------------------------------------
# The literal §9.4 scale
# ---------------------------------------------------------------------------------------


@pytest.mark.slow
def test_twenty_five_thousand_files_at_the_real_limit(tmp_path: Path) -> None:
    """The fixture §9.4 names, against the shipped max_files of 20 000."""
    root = tmp_path / "repo"
    root.mkdir()
    for i in range(25_000):
        (root / f"m{i:05d}.py").write_bytes(b"x=1\n")

    result = walk_repository(root)

    assert len(result.files) == 20_000
    assert result.truncated
    assert "max_files" in {t.reason for t in result.truncations}
