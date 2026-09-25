"""The reviewer's side of an analysis: findings, disagreement, and verification.

A finding is evidence, not a verdict. The staged view shows each finding as it streams,
and the reviewer can mark it ``agree`` or ``disagree`` with a reason. Feedback never
edits the canonical artifacts (``score.json`` and ``report.html`` stay byte-stable); it
is stored beside them and shown next to them, and it can be exported.

Verification (PROTOCOL-R3 K1): when the local worker reports that the Docker sandbox is
available, a reviewer can ask for one reviewed selection to be verified with the
project's own tests, and the pull-request path requires that verdict.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from quanta.core.fixes import FixPlan, review
from quanta.errors import Reject
from quanta.verify.service import CAPABILITY_TTL_S
from quanta.web.auth import Identity, auth
from quanta.web.db import timestamp
from quanta.web.jobs import Job, JobRegistry
from quanta.web.routes import _artifact, _job_or_404, _registry

router = APIRouter()

FINDING_ID = r"^[a-z_]{3,32}-[0-9a-f]{16}$"
#: Feedback rows per analysis and user. Far above any real inventory we have seen.
MAX_FEEDBACK = 5000
#: Verification is expensive; one open request per person at a time.
MAX_OPEN_VERIFICATIONS = 1


class Feedback(BaseModel):
    verdict: Literal["agree", "disagree"]
    reason: str = Field(default="", max_length=500)


class VerifyRequest(BaseModel):
    selected: list[str] = Field(min_length=1, max_length=200)
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")


def reviewer(request: Request) -> tuple[Identity | None, str]:
    """The person giving feedback. Without sign-in (local mode) there is one reviewer."""
    service = auth(request)
    identity = service.identity(request, required=service.settings.required)
    if identity:
        service.csrf(request, identity)
        return identity, identity.user_id
    return None, "local"


def reader(request: Request) -> str:
    # Access to the analysis itself is enforced by _job_or_404; this only picks whose marks.
    identity = auth(request).identity(request, required=False)
    return identity.user_id if identity else "local"


def verification_available(registry: JobRegistry) -> bool:
    """True only when a local worker has recently proved it can run the sandbox."""
    verify = registry.settings.verify
    if verify.mode != "auto" or not verify.web or registry.settings.cloud.enabled:
        return False
    with registry.db.connect() as conn:
        row = conn.execute(
            "SELECT value,updated_at FROM capabilities WHERE name='verify'"
        ).fetchone()
    if row is None or row["value"] != "1":
        return False
    age = time.time() - datetime.fromisoformat(row["updated_at"]).timestamp()
    return age <= CAPABILITY_TTL_S


def _streamed(job: Job) -> list[dict[str, Any]]:
    return [item for e in job.events if e.event == "findings" for item in e.data.get("items", [])]


def _findings(request: Request, job: Job) -> list[dict[str, Any]]:
    if job.status != "succeeded":
        return _streamed(job)
    try:
        payload = json.loads(_artifact(request, job, "findings.json"))
    except Reject:
        # A cached corpus from before findings.json existed has no findings to show.
        return []
    findings: list[dict[str, Any]] = payload.get("findings", [])
    return findings


def _feedback(registry: JobRegistry, job_id: str, user_id: str) -> dict[str, dict[str, str]]:
    with registry.db.connect() as conn:
        rows = conn.execute(
            "SELECT finding_id,verdict,reason,updated_at FROM finding_feedback "
            "WHERE job_id=? AND user_id=? ORDER BY finding_id",
            (job_id, user_id),
        ).fetchall()
    return {
        r["finding_id"]: {"verdict": r["verdict"], "reason": r["reason"], "at": r["updated_at"]}
        for r in rows
    }


@router.get("/analyses/{job_id}/findings")
def findings(request: Request, job_id: str) -> dict[str, Any]:
    job = _job_or_404(request, job_id)
    items = _findings(request, job)
    return {
        "findings": items,
        "feedback": _feedback(_registry(request), job.id, reader(request)),
    }


@router.put("/analyses/{job_id}/findings/{finding_id}/feedback")
def put_feedback(request: Request, job_id: str, finding_id: str, body: Feedback) -> dict[str, Any]:
    _, user_id = reviewer(request)
    job = _job_or_404(request, job_id)
    _check_finding_id(finding_id)
    # Feedback is only accepted on a finding the analysis actually produced. While a job
    # is running, the id must at least have been streamed.
    known = {f["id"] for f in _findings(request, job)}
    if finding_id not in known:
        raise Reject("NOT_FOUND", "no such finding in this analysis")
    registry = _registry(request)
    with registry.db.connect(write=True) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM finding_feedback WHERE job_id=? AND user_id=?",
            (job.id, user_id),
        ).fetchone()[0]
        if count >= MAX_FEEDBACK:
            raise Reject("RATE_LIMITED", "feedback limit reached for this analysis")
        conn.execute(
            "INSERT INTO finding_feedback(job_id,user_id,finding_id,verdict,reason,updated_at) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(job_id,user_id,finding_id) DO UPDATE SET "
            "verdict=excluded.verdict,reason=excluded.reason,updated_at=excluded.updated_at",
            (job.id, user_id, finding_id, body.verdict, body.reason.strip(), timestamp()),
        )
    return {"finding_id": finding_id, "verdict": body.verdict, "reason": body.reason.strip()}


@router.delete("/analyses/{job_id}/findings/{finding_id}/feedback")
def delete_feedback(request: Request, job_id: str, finding_id: str) -> dict[str, Any]:
    _, user_id = reviewer(request)
    job = _job_or_404(request, job_id)
    _check_finding_id(finding_id)
    with _registry(request).db.connect(write=True) as conn:
        conn.execute(
            "DELETE FROM finding_feedback WHERE job_id=? AND user_id=? AND finding_id=?",
            (job.id, user_id, finding_id),
        )
    return {"finding_id": finding_id, "verdict": None}


@router.get("/analyses/{job_id}/feedback")
def feedback_export(request: Request, job_id: str) -> dict[str, Any]:
    """The reviewer's disagreements next to the findings they concern, for the report."""
    job = _job_or_404(request, job_id)
    marks = _feedback(_registry(request), job.id, reader(request))
    by_id = {f["id"]: f for f in _findings(request, job)}
    rows = [
        {
            "finding_id": fid,
            **mark,
            "file": by_id.get(fid, {}).get("file"),
            "line": by_id.get(fid, {}).get("line"),
            "name": by_id.get(fid, {}).get("name"),
            "scored": by_id.get(fid, {}).get("scored"),
        }
        for fid, mark in marks.items()
    ]
    return {
        "job_id": job.id,
        "agree": sum(r["verdict"] == "agree" for r in rows),
        "disagree": sum(r["verdict"] == "disagree" for r in rows),
        "disputed_scored": sum(r["verdict"] == "disagree" and bool(r["scored"]) for r in rows),
        "items": rows,
    }


def _check_finding_id(finding_id: str) -> None:
    import re

    if not re.fullmatch(FINDING_ID, finding_id):
        raise Reject("NOT_FOUND", "no such finding")


def _plan(request: Request, job: Job) -> FixPlan:
    return FixPlan.model_validate_json(_artifact(request, job, "fixes.json"))


def _verification_row(row: Any) -> dict[str, Any]:
    result = json.loads(row["result"]) if row["result"] else {}
    return {
        "id": row["id"],
        "digest": row["digest"],
        "status": row["status"],
        "verdict": row["verdict"],
        "created_at": row["created_at"],
        "finished_at": row["finished_at"],
        **({"result": result} if result else {}),
    }


def latest_verification(registry: JobRegistry, job_id: str, digest: str) -> dict[str, Any] | None:
    with registry.db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM verifications WHERE job_id=? AND digest=? "
            "ORDER BY created_at DESC, id DESC LIMIT 1",
            (job_id, digest),
        ).fetchone()
    return _verification_row(row) if row else None


@router.get("/verification")
def verification_status(request: Request) -> dict[str, Any]:
    registry = _registry(request)
    return {
        "available": verification_available(registry),
        "mode": registry.settings.verify.mode,
    }


@router.post("/analyses/{job_id}/verify", status_code=202)
def request_verification(request: Request, job_id: str, body: VerifyRequest) -> dict[str, Any]:
    _, user_id = reviewer(request)
    job = _job_or_404(request, job_id)
    registry = _registry(request)
    if job.status != "succeeded" or job.cached:
        raise Reject("FIX_UNAVAILABLE", "Verification needs a completed live scan.")
    if not verification_available(registry):
        raise Reject(
            "SANDBOX_UNAVAILABLE",
            "Verification needs a local worker with Docker. Start one with `quanta worker`.",
        )
    result = review(_plan(request, job), body.selected)
    if result["digest"] != body.digest:
        raise Reject("REVIEW_STALE", "Review the current diff before verifying it.")
    with registry.db.connect(write=True) as conn:
        existing = conn.execute(
            "SELECT * FROM verifications WHERE job_id=? AND digest=? "
            "AND status IN ('queued','running','done') ORDER BY created_at DESC LIMIT 1",
            (job.id, body.digest),
        ).fetchone()
        if existing:
            return _verification_row(existing)
        open_count = conn.execute(
            "SELECT COUNT(*) FROM verifications WHERE user_id=? AND status IN ('queued','running')",
            (user_id,),
        ).fetchone()[0]
        if open_count >= MAX_OPEN_VERIFICATIONS:
            raise Reject("RATE_LIMITED", "One verification at a time. Wait for the current one.")
        vid = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO verifications(id,job_id,user_id,digest,selected,status,created_at) "
            "VALUES(?,?,?,?,?,'queued',?)",
            (vid, job.id, user_id, body.digest, json.dumps(sorted(body.selected)), timestamp()),
        )
        row = conn.execute("SELECT * FROM verifications WHERE id=?", (vid,)).fetchone()
    return _verification_row(row)


@router.get("/analyses/{job_id}/verification")
def get_verification(request: Request, job_id: str, digest: str) -> dict[str, Any]:
    job = _job_or_404(request, job_id)
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise Reject("SCHEMA_INVALID", "digest must be 64 hex characters")
    record = latest_verification(_registry(request), job.id, digest)
    return {
        "available": verification_available(_registry(request)),
        "verification": record,
    }
