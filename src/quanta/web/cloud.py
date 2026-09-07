"""Bounded cloud execution with durable claims, no credentials in the sandbox."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

from fastapi import APIRouter, Request
from vercel import sandbox
from vercel.sandbox import NetworkPolicy, SandboxResources, SnapshotSource

from quanta.core.models import AnalysisMeta, Provenance, ScoreReport
from quanta.errors import Reject
from quanta.web.auth import auth
from quanta.web.db import event, timestamp
from quanta.web.jobs import JobRegistry
from quanta.web.routes import _job_or_404, _registry
from quanta.web.store import ARTIFACT_NAMES, DatabaseArtifactStore

router = APIRouter()


def sweep(registry: JobRegistry) -> None:
    with registry.db.connect(write=True) as conn:
        expired = conn.execute(
            "SELECT id FROM jobs WHERE status='running' AND claimed_at<?",
            (timestamp(time.time() - 260),),
        ).fetchall()
        for row in expired:
            conn.execute(
                "UPDATE jobs SET status='timeout',finished_at=?,error_code='ANALYSIS_TIMEOUT' "
                "WHERE id=?",
                (timestamp(), row[0]),
            )
            event(
                conn,
                row[0],
                "error",
                {
                    "error_code": "ANALYSIS_TIMEOUT",
                    "detail": "The scan exceeded its time limit. Try a smaller repository.",
                },
            )
        conn.execute(
            "DELETE FROM jobs WHERE status IN ('succeeded','failed','timeout','queued') "
            "AND created_at<?",
            (timestamp(time.time() - registry.settings.retention.artifact_ttl_days * 86400),),
        )
        conn.execute("DELETE FROM sessions WHERE expires_at<?", (timestamp(),))
        conn.execute("DELETE FROM oauth_states WHERE expires_at<?", (timestamp(),))


async def execute(registry: JobRegistry, job_id: str) -> None:
    cfg = registry.settings
    if not cfg.cloud.enabled or not cfg.cloud.sandbox_snapshot:
        raise Reject("SANDBOX_UNAVAILABLE", "Hosted scanning is being configured. Try the sample.")
    sweep(registry)
    lease = str(uuid.uuid4())
    with registry.db.connect(write=True) as conn:
        row = conn.execute(
            "UPDATE jobs SET status='running',worker_id=?,claimed_at=?,attempts=1 "
            "WHERE id=? AND status='queued' AND "
            "(SELECT COUNT(*) FROM jobs WHERE status='running')<2 RETURNING *",
            (lease, timestamp(), job_id),
        ).fetchone()
        if row is None:
            return
        metadata = dict(row)
        event(conn, job_id, "status", {"status": "running"})
    try:
        async with asyncio.timeout(cfg.cloud.timeout_seconds + 30):
            async with sandbox.create_sandbox(
                source=SnapshotSource(snapshot_id=cfg.cloud.sandbox_snapshot),
                resources=SandboxResources(vcpus=1, memory=2048),
                execution_time_limit=cfg.cloud.timeout_seconds,
                network_policy=NetworkPolicy.custom({"github.com": (), "api.github.com": ()}),
                persistent=False,
                destroy=True,
                tags={"app": "quanta", "job": job_id},
            ) as box:
                payload = {
                    "job": {
                        key: metadata[key] for key in ("repo_owner", "repo_name", "commit_sha")
                    },
                    "settings": cfg.scanner_settings().model_dump(mode="json"),
                }
                await box.fs.write_text("quanta-input.json", json.dumps(payload))
                for phase in ("acquire", "analyze"):
                    if phase == "analyze":
                        await box.update_network_policy(NetworkPolicy.deny_all())
                    with registry.db.connect(write=True) as conn:
                        event(
                            conn,
                            job_id,
                            "progress",
                            {"phase": phase, "pct": 12 if phase == "acquire" else 45},
                        )
                    result = await box.run_process(
                        ".venv/bin/python",
                        ["-I", "-m", "quanta.web.cloud_entry", phase],
                        cwd=box.cwd,
                        kill_after=cfg.ingest.clone_timeout_s
                        if phase == "acquire"
                        else cfg.analysis.max_job_seconds,
                        capture_output=False,
                    )
                    if result.returncode != 0:
                        try:
                            error = json.loads(await box.fs.read_text("quanta-error.json"))
                            raise Reject(error["code"], error["detail"])
                        except (ValueError, KeyError):
                            raise Reject(
                                "INTERNAL", "The isolated scanner could not finish."
                            ) from None
                artifacts = {}
                for name in ARTIFACT_NAMES:
                    async with box.fs.open("quanta-output/" + name, "rb") as handle:
                        data = await handle.read(DatabaseArtifactStore.MAX_BYTES + 1)
                    if len(data) > DatabaseArtifactStore.MAX_BYTES:
                        raise Reject("REPO_TOO_LARGE", "The report exceeds the free output limit.")
                    artifacts[name] = data
                if sum(len(data) for data in artifacts.values()) > DatabaseArtifactStore.MAX_BYTES:
                    raise Reject("REPO_TOO_LARGE", "The report exceeds the free output limit.")
                score = ScoreReport.model_validate_json(artifacts["score.json"])
                meta = AnalysisMeta.model_validate_json(artifacts["meta.json"])
                if score.provenance.commit_sha != metadata["commit_sha"]:
                    raise Reject("SHA_MISMATCH")
                with registry.db.connect(write=True) as conn:
                    owned = conn.execute(
                        "SELECT id FROM jobs WHERE id=? AND worker_id=? AND status='running'",
                        (job_id, lease),
                    ).fetchone()
                    if not owned:
                        return
                    if not isinstance(registry.store, DatabaseArtifactStore):
                        raise Reject(
                            "SANDBOX_UNAVAILABLE", "Cloud scans require durable artifact storage."
                        )
                    for name, data in artifacts.items():
                        registry.store.put_in_transaction(conn, job_id, name, data)
                    for step in meta.steps:
                        event(conn, job_id, "step", step.model_dump(mode="json"))
                    conn.execute(
                        "UPDATE jobs SET status='succeeded',finished_at=?,"
                        "agility_score=?,truncated=? "
                        "WHERE id=?",
                        (timestamp(), score.agility_score, int(score.coverage.truncated), job_id),
                    )
                    provenance = Provenance.model_validate(score.provenance)
                    conn.execute(
                        "INSERT INTO analysis_cache(provenance,job_id,created_at) VALUES(?,?,?) "
                        "ON CONFLICT(provenance) DO UPDATE SET job_id=excluded.job_id,"
                        "created_at=excluded.created_at",
                        (provenance.cache_key(), job_id, timestamp()),
                    )
                    event(
                        conn,
                        job_id,
                        "done",
                        {"status": "succeeded", "agility_score": score.agility_score},
                    )
    except Exception as exc:
        code = (
            exc.code
            if isinstance(exc, Reject)
            else "ANALYSIS_TIMEOUT"
            if isinstance(exc, TimeoutError)
            else "SANDBOX_UNAVAILABLE"
        )
        detail = (
            exc.detail
            if isinstance(exc, Reject)
            else "The hosted scanner could not finish. Please try again later."
        )
        with registry.db.connect(write=True) as conn:
            changed = conn.execute(
                "UPDATE jobs SET status='failed',finished_at=?,error_code=? "
                "WHERE id=? AND worker_id=? AND status='running'",
                (timestamp(), code, job_id, lease),
            ).rowcount
            if changed:
                event(conn, job_id, "error", {"error_code": code, "detail": detail})


@router.post("/analyses/{job_id}/run")
async def run(request: Request, job_id: str) -> dict[str, Any]:
    identity = auth(request).identity(request)
    if identity is None:
        raise Reject("AUTH_REQUIRED")
    auth(request).csrf(request, identity)
    _job_or_404(request, job_id)
    await execute(_registry(request), job_id)
    return _job_or_404(request, job_id).public()
