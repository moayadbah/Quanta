"""Atomic, bounded artifact paths. Source checkouts never enter this store."""

from __future__ import annotations

import base64
import os
import tempfile
import uuid
import zlib
from pathlib import Path
from typing import Any

from quanta.errors import Reject
from quanta.web.db import Database

REQUIRED_ARTIFACT_NAMES = frozenset({"cdg.json", "score.json", "meta.json", "report.html"})
ARTIFACT_NAMES = REQUIRED_ARTIFACT_NAMES | {"fixes.json"}


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
        return all(self.path(job_id, name).is_file() for name in REQUIRED_ARTIFACT_NAMES)


class DatabaseArtifactStore(ArtifactStore):
    """Small compressed artifacts in Postgres; function disks are never durable state."""

    MAX_BYTES = 4_000_000

    def __init__(self, root: Path, database: Database) -> None:
        super().__init__(root)
        self.db = database

    def put_in_transaction(self, conn: Any, job_id: str, name: str, data: bytes) -> None:
        self.path(job_id, name)
        if len(data) > self.MAX_BYTES:
            raise Reject("REPO_TOO_LARGE", "Analysis output exceeds the free hosting limit.")
        encoded = base64.b64encode(zlib.compress(data)).decode()
        conn.execute(
            "INSERT INTO artifact_blobs(job_id,name,data) VALUES(?,?,?) "
            "ON CONFLICT(job_id,name) DO UPDATE SET data=excluded.data",
            (job_id, name, encoded),
        )

    def put(self, job_id: str, name: str, data: bytes) -> Path:
        with self.db.connect(write=True) as conn:
            self.put_in_transaction(conn, job_id, name, data)
        return self.path(job_id, name)

    def open(self, job_id: str, name: str) -> bytes:
        self.path(job_id, name)
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT data FROM artifact_blobs WHERE job_id=? AND name=?", (job_id, name)
            ).fetchone()
        if not row:
            raise Reject("NOT_FINISHED", "This artifact is not available.")
        decoder = zlib.decompressobj()
        data = decoder.decompress(base64.b64decode(row[0]), self.MAX_BYTES + 1)
        if len(data) > self.MAX_BYTES or not decoder.eof:
            raise Reject("INTERNAL", "Artifact exceeds its storage limit.")
        return data

    def complete(self, job_id: str) -> bool:
        self.directory(job_id)
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT name FROM artifact_blobs WHERE job_id=?", (job_id,)
            ).fetchall()
        return REQUIRED_ARTIFACT_NAMES.issubset({row[0] for row in rows})
