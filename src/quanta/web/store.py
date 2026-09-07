"""Atomic, bounded artifact paths. Source checkouts never enter this store."""

from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path

from quanta.errors import Reject

ARTIFACT_NAMES = frozenset({"cdg.json", "score.json", "meta.json", "report.html"})


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def directory(self, job_id: str) -> Path:
        try:
            parsed = uuid.UUID(job_id)
            if parsed.version != 4 or str(parsed) != job_id:
                raise ValueError("not a canonical UUIDv4")
        except ValueError as exc:
            raise Reject("NOT_FOUND", "no such artifact") from exc
        path = self.root / job_id
        if path.is_symlink() or not path.resolve().is_relative_to(self.root):
            raise Reject("NOT_FOUND", "no such artifact")
        return path

    def path(self, job_id: str, name: str) -> Path:
        if name not in ARTIFACT_NAMES:
            raise Reject("NOT_FOUND", "no such artifact")
        path = self.directory(job_id) / name
        if path.is_symlink() or not path.resolve().is_relative_to(self.root):
            raise Reject("NOT_FOUND", "no such artifact")
        return path

    def put(self, job_id: str, name: str, data: bytes) -> Path:
        target = self.path(job_id, name)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as handle:
            temporary = Path(handle.name)
            try:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
        try:
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        return target

    def open(self, job_id: str, name: str) -> bytes:
        return self.path(job_id, name).read_bytes()

    def complete(self, job_id: str) -> bool:
        return all(self.path(job_id, name).is_file() for name in ARTIFACT_NAMES)
