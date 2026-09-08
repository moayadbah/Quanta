"""Durable SQLite/PostgreSQL queue, atomic leases and ordered events.

Every transaction opens its own connection. API threads and separate worker processes
therefore never share a connection or an in-memory source of job truth.
"""

from __future__ import annotations

import json
import re
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
CREATE TABLE IF NOT EXISTS oauth_states (
 id TEXT PRIMARY KEY, verifier TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, login TEXT NOT NULL,
 token TEXT NOT NULL, csrf TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analysis_access (
 job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL, PRIMARY KEY(job_id,user_id)
);
CREATE TABLE IF NOT EXISTS usage_counters (
 id TEXT PRIMARY KEY, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pull_requests (
 id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL, digest TEXT NOT NULL, status TEXT NOT NULL,
 url TEXT, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifact_blobs (
 job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
 name TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(job_id,name)
);
"""

TABLE_NAMES = tuple(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SCHEMA))


def protect_postgres_schema(conn: PostgresConnection) -> None:
    """Keep server-owned data private, including on Supabase's older default grants."""
    # This is an application-only schema. Never expose it through the Data API.
    # All identifiers below come from our static schema or this fixed role allowlist.
    roles = ["PUBLIC"]
    for role in ("anon", "authenticated", "service_role"):
        if conn.execute("SELECT 1 FROM pg_roles WHERE rolname=?", (role,)).fetchone():
            roles.append(role)
    for role in roles:
        conn.execute(f"REVOKE ALL ON SCHEMA quanta FROM {role}")
        conn.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA quanta FROM {role}")
        conn.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA quanta FROM {role}")
    for table in TABLE_NAMES:
        conn.execute(f"ALTER TABLE quanta.{table} ENABLE ROW LEVEL SECURITY")
    # No browser policies: requests go through FastAPI's ownership/CSRF checks.
    # The server connects as the schema owner and can therefore use these tables.


def timestamp(epoch: float | None = None) -> str:
    return datetime.fromtimestamp(time.time() if epoch is None else epoch, UTC).isoformat()


def event(conn: Any, job_id: str, kind: str, data: dict[str, Any]) -> None:
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


class Record(dict[str, Any]):
    def __getitem__(self, key: str | int) -> Any:
        return list(self.values())[key] if isinstance(key, int) else super().__getitem__(key)


class PostgresConnection:
    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def execute(self, sql: str, values: tuple[Any, ...] = ()) -> Any:
        return self.connection.execute(sql.replace("?", "%s"), values)


class Database:
    def __init__(self, path: Path, url: str = "") -> None:
        self.path = path.resolve()
        self.url = url
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            if url:
                schema = SCHEMA.replace(
                    "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY"
                )
                # Serialize startup migrations across cold function instances.
                conn.execute("SELECT pg_advisory_xact_lock(72682417)")
                conn.execute("CREATE SCHEMA IF NOT EXISTS quanta")
                for statement in schema.split(";"):
                    if statement.strip():
                        conn.execute(statement)
                protect_postgres_schema(conn)
            else:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript(SCHEMA)

    @contextmanager
    def connect(self, *, write: bool = False) -> Iterator[Any]:
        if self.url:
            import psycopg

            def row_factory(cursor: Any) -> Any:
                names = [column.name for column in cursor.description] if cursor.description else []
                return lambda values: Record(zip(names, values, strict=True))

            with psycopg.connect(
                self.url,
                connect_timeout=10,
                row_factory=row_factory,
                # Supabase's transaction pooler cannot retain prepared statements.
                prepare_threshold=None,
            ) as pg:
                wrapper = PostgresConnection(pg)
                # Transaction-local settings survive every request in transaction
                # pooling without leaking the search path to another pool client.
                wrapper.execute("SET LOCAL search_path = quanta, pg_catalog")
                if write:
                    wrapper.execute("SELECT pg_advisory_xact_lock(72682417)")
                yield wrapper
            return
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
