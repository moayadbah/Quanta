"""Database-backed job registry. Submitting never launches an analyzer in the API."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

import httpx

from quanta.config import Settings, get_settings
from quanta.core.analyze import STEP_TITLES
from quanta.core.ingest import RepoMetadata, parse_repo_url, resolve_metadata
from quanta.core.models import Provenance, StepRecord
from quanta.errors import Reject
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version
from quanta.web.db import Database, event, timestamp
from quanta.web.store import ARTIFACT_NAMES, ArtifactStore

JobStatus = Literal["queued", "running", "succeeded", "failed", "timeout"]
TERMINAL_STATUSES = frozenset({"succeeded", "failed", "timeout"})


@dataclass
class JobEvent:
    id: int
    event: str
    data: dict[str, Any]


@dataclass
class Job:
    id: str
    repo_url: str
    status: JobStatus = "queued"
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    error_code: str | None = None
    error_detail: str | None = None
    agility_score: float | None = None
    artifact_dir: Path | None = None
    cached: bool = False
    reused: bool = False
    events: list[JobEvent] = field(default_factory=list)
    steps: list[StepRecord] = field(default_factory=list)
    reported_phase: str | None = None
    reported_progress: int | None = None

    def add_event(self, kind: str, data: dict[str, Any]) -> JobEvent:
        record = JobEvent(len(self.events) + 1, kind, data)
        self.events.append(record)
        return record

    @property
    def phase(self) -> str | None:
        return self.steps[-1].id if self.steps else self.reported_phase

    @property
    def progress(self) -> int:
        if self.status == "succeeded":
            return 100
        if self.reported_progress is not None:
            return self.reported_progress
        done = sum(s.status in {"done", "skipped"} for s in self.steps)
        return int(100 * done / len(STEP_TITLES))

    def public(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "job_id": self.id,
            "status": self.status,
            "phase": self.phase,
            "progress": self.progress,
            "cached": self.cached,
            "repo_url": self.repo_url,
        }
        if self.agility_score is not None:
            body["agility_score"] = self.agility_score
        if self.status == "succeeded":
            body["report_url"] = f"/api/v1/analyses/{self.id}/report"
        if self.error_code:
            body["error_code"] = self.error_code
            body["detail"] = self.error_detail
        return body


class JobRegistry:
    def __init__(
        self,
        artifact_root: Path,
        db_path: Path | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = (settings or get_settings()).model_copy(deep=True)
        self.store = ArtifactStore(artifact_root)
        self.artifact_root = self.store.root
        self.db = Database(
            db_path or (self.artifact_root.parent / "quanta.db"),
            self.settings.cloud.database_url.get_secret_value(),
        )
        if self.settings.cloud.enabled:
            from quanta.web.store import DatabaseArtifactStore

            self.store = DatabaseArtifactStore(artifact_root, self.db)

    def shutdown(self) -> None:
        """Workers have an independent lifecycle; API shutdown cannot cancel their jobs."""

    def drain(self) -> None:
        """Compatibility for demo consumers; progress is already durable in SQLite."""

    def get(self, job_id: str) -> Job | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                return None
            records = conn.execute(
                "SELECT id,message FROM job_events WHERE job_id=? ORDER BY id",
                (job_id,),
            ).fetchall()
        job = Job(
            id=row["id"],
            repo_url=f"https://github.com/{row['repo_owner']}/{row['repo_name']}",
            status=cast(JobStatus, row["status"]),
            agility_score=row["agility_score"],
            error_code=row["error_code"],
            cached=bool(row["cached"]),
            created_at=datetime.fromisoformat(row["created_at"]).timestamp(),
            finished_at=(
                datetime.fromisoformat(row["finished_at"]).timestamp()
                if row["finished_at"]
                else None
            ),
            artifact_dir=self.store.directory(job_id),
        )
        for record in records:
            payload = json.loads(record["message"])
            job.events.append(JobEvent(record["id"], payload["event"], payload["data"]))
            if payload["event"] == "plan":
                job.steps.clear()
            elif payload["event"] == "step":
                step = StepRecord.model_validate(payload["data"])
                job.steps = [s for s in job.steps if s.id != step.id] + [step]
            elif payload["event"] == "error":
                job.error_detail = payload["data"].get("detail")
            elif payload["event"] == "progress":
                job.reported_phase = payload["data"].get("phase")
                job.reported_progress = min(100, max(0, int(payload["data"].get("pct", 0))))
        return job

    def active_count(self) -> int:
        with self.db.connect() as conn:
            return int(
                conn.execute(
                    "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')",
                ).fetchone()[0]
            )

    def submit(
        self, repo_url: str, user_id: str | None = None, client: httpx.Client | None = None
    ) -> Job:
        owner, name = parse_repo_url(repo_url, self.settings)
        metadata = resolve_metadata(owner, name, self.settings, client=client)
        return self.enqueue(metadata, user_id)

    def enqueue(self, metadata: RepoMetadata, user_id: str | None = None) -> Job:
        """Deduplicate pinned work and enforce the queue cap under one write lock."""
        owner, name = metadata.owner.lower(), metadata.name.lower()
        provenance = Provenance(
            repo=f"{owner}/{name}",
            commit_sha=metadata.commit_sha,
            analyzer_version=analyzer_version(),
            crypto_ruleset_version=CRYPTO_RULESET_VERSION,
        )
        reused = False
        with self.db.connect(write=True) as conn:
            cached = conn.execute(
                "SELECT job_id FROM analysis_cache WHERE provenance=?",
                (provenance.cache_key(),),
            ).fetchone()
            existing_id = cached[0] if cached and self.store.complete(cached[0]) else None
            if existing_id is None:
                running = conn.execute(
                    "SELECT id FROM jobs WHERE repo_owner=? AND repo_name=? AND commit_sha=? "
                    "AND analyzer_version=? AND status IN ('queued','running') LIMIT 1",
                    (owner, name, metadata.commit_sha, analyzer_version()),
                ).fetchone()
                existing_id = running[0] if running else None
            if existing_id:
                job_id = existing_id
                reused = True
            else:
                if user_id:
                    self.charge(conn, user_id)
                depth = conn.execute(
                    "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')",
                ).fetchone()[0]
                if depth >= self.settings.api.max_queue_depth:
                    raise Reject("RATE_LIMITED", "the queue is full; try again shortly")
                job_id = str(uuid.uuid4())
                conn.execute(
                    "INSERT INTO jobs(id,repo_owner,repo_name,commit_sha,analyzer_version,status,"
                    "created_at,default_branch,size_kb) VALUES(?,?,?,?,?,'queued',?,?,?)",
                    (
                        job_id,
                        owner,
                        name,
                        metadata.commit_sha,
                        analyzer_version(),
                        timestamp(),
                        metadata.default_branch,
                        metadata.size_kb,
                    ),
                )
                event(conn, job_id, "status", {"status": "queued"})
                event(
                    conn,
                    job_id,
                    "plan",
                    {
                        "steps": [{"id": sid, "title": title} for sid, title in STEP_TITLES],
                    },
                )
            if user_id:
                conn.execute(
                    "INSERT INTO analysis_access(job_id,user_id) VALUES(?,?) "
                    "ON CONFLICT(job_id,user_id) DO NOTHING",
                    (job_id, user_id),
                )
        job = self.get(job_id)
        if job is None:
            raise Reject("INTERNAL", "job disappeared during submission")
        job.reused = reused
        return job

    def charge(self, conn: Any, user_id: str) -> None:
        """Pessimistic reservations include failures; cache hits do not consume compute."""
        now = timestamp()
        limits = [
            (f"user:{user_id}:{now[:10]}", self.settings.product.scans_per_user_day),
            (f"global:{now[:7]}", self.settings.product.scans_per_month),
        ]
        for key, limit in limits:
            conn.execute(
                "INSERT INTO usage_counters(id,used) VALUES(?,0) ON CONFLICT(id) DO NOTHING", (key,)
            )
            changed = conn.execute(
                "UPDATE usage_counters SET used=used+1 WHERE id=? AND used<?", (key, limit)
            ).rowcount
            if not changed:
                raise Reject(
                    "QUOTA_EXCEEDED",
                    "The free scan allowance is used up. "
                    "Daily limits reset at midnight UTC; shared limits reset monthly.",
                )

    def usage(self, user_id: str) -> dict[str, int]:
        now = timestamp()
        with self.db.connect() as conn:

            def used(key: str) -> int:
                row = conn.execute("SELECT used FROM usage_counters WHERE id=?", (key,)).fetchone()
                return int(row[0]) if row else 0

            return {
                "daily_used": used(f"user:{user_id}:{now[:10]}"),
                "daily_limit": self.settings.product.scans_per_user_day,
                "monthly_used": used(f"global:{now[:7]}"),
                "monthly_limit": self.settings.product.scans_per_month,
            }

    def adopt_cached(self, job: Job) -> None:
        """Persist a demo replay using the same artifact boundary as live jobs."""
        destination = self.store.directory(job.id)
        if job.artifact_dir and job.artifact_dir.resolve() != destination:
            for name in ARTIFACT_NAMES:
                source = job.artifact_dir / name
                if source.is_file():
                    self.store.put(job.id, name, source.read_bytes())
        owner, name = parse_repo_url(job.repo_url)
        with self.db.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO jobs(id,repo_owner,repo_name,commit_sha,analyzer_version,status,"
                "created_at,finished_at,agility_score,cached) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    job.id,
                    owner,
                    name,
                    "0" * 40,
                    analyzer_version(),
                    job.status,
                    timestamp(job.created_at),
                    timestamp(job.finished_at) if job.finished_at else None,
                    job.agility_score,
                    int(job.cached),
                ),
            )
            for record in job.events:
                event(conn, job.id, record.event, record.data)
        job.artifact_dir = destination

    def heartbeat_age(self) -> float | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT MAX(last_seen) FROM worker_heartbeats").fetchone()
        return (
            max(0.0, time.time() - datetime.fromisoformat(row[0]).timestamp()) if row[0] else None
        )
