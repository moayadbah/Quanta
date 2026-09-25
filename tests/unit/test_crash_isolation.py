"""A file that crashes the parser degrades that file, never the analysis (D17).

Round two: CPython's generated ``pydoc_data/topics.py`` (675 KB of implicitly
concatenated strings) overflowed the native stack of LibCST's parser and killed the whole
process on a sampled repository. Large files now parse in a disposable child process.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from quanta.core import detect
from quanta.core.detect import detect_repository


def _crash_like_a_native_stack_overflow(path: str, root: str, connection: object) -> None:
    """Stands in for a native crash: the child dies without sending a result."""
    os._exit(3)


def test_large_files_are_parsed_in_a_child_with_the_same_result(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    body = "import hashlib\nhashlib.md5(b'')\n" + "X = 1\n" * 40_000
    (root / "big.py").write_text(body)
    assert (root / "big.py").stat().st_size >= detect.ISOLATE_BYTES
    result = detect_repository([root / "big.py"], root)
    assert result.unparseable == []
    assert [s.line for s in result.crypto_calls] == [2]
    assert result.module_roles == {"big": "source"}


def test_a_crashing_child_is_recorded_as_unparseable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "big.py").write_text("X = 1\n" * 40_000)
    (root / "ok.py").write_text("import hashlib\nhashlib.sha1(b'')\n")
    # Simulate a native crash in the child without depending on one existing.
    monkeypatch.setattr(detect, "_ISOLATED_TARGET", _crash_like_a_native_stack_overflow)
    result = detect_repository([root / "big.py", root / "ok.py"], root)
    assert [u.file for u in result.unparseable] == ["big.py"]
    assert "isolated" in result.unparseable[0].reason
    assert len(result.crypto_calls) == 1
