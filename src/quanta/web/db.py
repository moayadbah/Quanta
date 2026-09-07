"""Durable SQLite queue, atomic leases and ordered events.

Every transaction opens its own connection. API threads and separate worker processes
therefore never share a connection or an in-memory source of job truth.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, repo_owner TEXT NOT NULL, repo_name TEXT NOT NULL,
 commit_sha TEXT NOT NULL, analyzer_version TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('queued','running','succeeded','failed','timeout')),
 phase TEXT, attempts INTEGER NOT NULL DEFAULT 0, worker_id TEXT, claimed_at TEXT,
 created_at TEXT NOT NULL, finished_at TEXT, error_code TEXT, agility_score REAL,
 truncated INTEGER NOT NULL DEFAULT 0,
 default_branch TEXT NOT NULL DEFAULT 'HEAD', size_kb INTEGER NOT NULL DEFAULT 0,
 cached INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_jobs_queue ON jobs(status, created_at);
CREATE TABLE IF NOT EXISTS job_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
 ts TEXT NOT NULL, phase TEXT NOT NULL, done INTEGER, total INTEGER, message TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_job ON job_events(job_id, id);
CREATE TABLE IF NOT EXISTS analysis_cache (
 provenance TEXT PRIMARY KEY,
 job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS worker_heartbeats (
 id TEXT PRIMARY KEY, last_seen TEXT NOT NULL
);
"""


def timestamp(epoch: float | None = None) -> str:
    return datetime.fromtimestamp(time.time() if epoch is None else epoch, UTC).isoformat()


def event(conn: sqlite3.Connection, job_id: str, kind: str, data: dict[str, Any]) -> None:
    conn.execute(
        "INSERT INTO job_events(job_id,ts,phase,done,total,message) VALUES(?,?,?,?,?,?)",
        (
            job_id,
            timestamp(),
            data.get("phase", kind),
            data.get("done"),
            data.get("total"),
            json.dumps({"event": kind, "data": data}, sort_keys=True),
        ),
    )


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
