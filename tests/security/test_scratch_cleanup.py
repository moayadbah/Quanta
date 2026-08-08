"""DoD-C1 — the clone is deleted on **every** path, including failure and timeout.

INGEST-09 is unconditional for two reasons. Retaining third-party source is a data-handling
liability (git history carries author names and email addresses, which are personal data
under GDPR and Saudi Arabia's PDPL), and it raises a copyleft redistribution question that
simply does not arise if nothing is kept.

"On every path" is the part that rots quietly: a ``try``/``finally`` survives review and
then a later refactor moves the cleanup inside the ``try``. These tests fail if that
happens.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quanta.core.ingest import scratch_dir
from quanta.errors import Reject, Truncated


def test_scratch_is_removed_on_success() -> None:
    with scratch_dir() as path:
        (path / "cloned.py").write_text("x = 1\n")
        assert path.exists()
    assert not path.exists()


@pytest.mark.parametrize(
    "error",
    [
        Reject("CLONE_FAILED", "boom"),
        Truncated("max_files", 1, 2),
        RuntimeError("unexpected"),
        KeyboardInterrupt(),
    ],
)
def test_scratch_is_removed_on_every_failure(error: BaseException) -> None:
    """Including KeyboardInterrupt, which is not an Exception subclass."""
    captured: Path | None = None
    with pytest.raises(type(error)), scratch_dir() as path:
        captured = path
        (path / "cloned.py").write_text("x = 1\n")
        raise error

    assert captured is not None
    assert not captured.exists()


def test_scratch_is_removed_when_a_directory_is_read_only() -> None:
    """A read-only directory must not defeat cleanup.

    ``shutil.rmtree(ignore_errors=True)`` on its own fails here and reports nothing: a
    directory without the write bit cannot have its entries unlinked, so the tree
    survives silently. That is retained third-party source, which INGEST-09 forbids
    unconditionally.
    """
    with scratch_dir() as path:
        nested = path / "locked"
        nested.mkdir()
        (nested / "f.py").write_text("x = 1\n")
        nested.chmod(0o500)
        captured = path

    assert not captured.exists(), "read-only directory defeated INGEST-09 cleanup"


def test_scratch_is_removed_when_nested_directories_are_read_only() -> None:
    with scratch_dir() as path:
        deep = path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "f.py").write_text("x = 1\n")
        for d in (deep, deep.parent, deep.parent.parent):
            d.chmod(0o500)
        captured = path

    assert not captured.exists()


def test_cleanup_failure_never_masks_the_original_error() -> None:
    """Cleanup runs in a finally; raising there would hide why the job actually failed."""
    with pytest.raises(Reject) as exc, scratch_dir() as path:
        (path / "locked").mkdir()
        (path / "locked").chmod(0o000)
        raise Reject("CLONE_FAILED", "the real reason")

    assert exc.value.code == "CLONE_FAILED"
    assert exc.value.detail == "the real reason"


def test_scratch_directories_do_not_accumulate() -> None:
    seen = []
    for _ in range(5):
        with scratch_dir() as path:
            seen.append(path)
    assert not any(p.exists() for p in seen)
    assert len(set(seen)) == 5, "each job must get its own directory"


def test_scratch_is_not_inside_the_artifact_tree(tmp_path: Path) -> None:
    """INGEST-06: never clone into the artifact directory."""
    with scratch_dir() as path:
        assert not path.is_relative_to(tmp_path)
        assert "quanta-" in path.name
