"""Product endpoints: private history, selected fixes and an honest interactive sample."""

from __future__ import annotations

import json
import time
from functools import lru_cache
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from quanta.core.analyze import AnalysisOutcome, analyze_path
from quanta.core.fixes import FixPlan, review, safe_path
from quanta.core.models import Provenance
from quanta.core.readiness import standards
from quanta.errors import Reject
from quanta.resources import asset_path
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version
from quanta.web import sample as recorded_sample
from quanta.web.auth import auth, github_client
from quanta.web.db import timestamp
from quanta.web.pulls import open_pull
from quanta.web.routes import (
    _artifact,
    _enforce_rate_limit,
    _job_or_404,
    _registry,
)

router = APIRouter()


class Selection(BaseModel):
    selected: list[str] = Field(min_length=1, max_length=200)


class PullRequest(Selection):
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    #: The reviewer read the compatibility note (stored hashes, peers, protocols).
    acknowledge_compatibility: bool = False
    #: When the verdict is not ``verified``, the reviewer must name it to proceed.
    acknowledge_verdict: str | None = Field(default=None, max_length=32)


@router.get("/workspace")
def workspace(request: Request) -> dict[str, Any]:
    service, registry = auth(request), _registry(request)
    identity = service.identity(request, required=False)
    jobs = []
    if identity:
        with registry.db.connect() as conn:
            rows = conn.execute(
                "SELECT j.id FROM jobs j JOIN analysis_access a ON j.id=a.job_id "
                "WHERE a.user_id=? AND j.created_at>? ORDER BY j.created_at DESC LIMIT 20",
                (
                    identity.user_id,
                    timestamp(time.time() - registry.settings.retention.artifact_ttl_days * 86400),
                ),
            ).fetchall()
        for row in rows:
            job = registry.get(row[0])
            if job:
                jobs.append({**job.public(), "created_at": job.created_at})
    cloud = registry.settings.cloud
    return {
        "jobs": jobs,
        "usage": registry.usage(identity.user_id) if identity else None,
        "limits": {
            "daily": registry.settings.product.scans_per_user_day,
            "monthly": registry.settings.product.scans_per_month,
            "repo_mb": registry.settings.ingest.max_repo_kb // 1000,
        },
        "hosted": cloud.enabled,
        "retention_days": registry.settings.retention.artifact_ttl_days,
        "scan_available": bool(cloud.sandbox_snapshot and cloud.database_url.get_secret_value())
        if cloud.enabled
        else registry.settings.deployment == "local",
    }


def _plan(request: Request, job_id: str) -> FixPlan:
    job = _job_or_404(request, job_id)
    try:
        return FixPlan.model_validate_json(_artifact(request, job, "fixes.json"))
    except Reject:
        if job.status == "succeeded":
            return FixPlan()
        raise


@router.get("/analyses/{job_id}/fixes")
def fixes(request: Request, job_id: str) -> dict[str, Any]:
    return _plan(request, job_id).public()


@router.get("/me")
def me(request: Request) -> dict[str, Any]:
    """The signed-in account and its public repositories, ready to scan with one click."""
    identity = auth(request).identity(request)
    if identity is None:
        raise Reject("AUTH_REQUIRED")
    try:
        with github_client(identity.token) as client:
            profile = client.get("/user")
            listing = client.get(
                "/user/repos",
                params={
                    "visibility": "public",
                    "affiliation": "owner",
                    "sort": "pushed",
                    "per_page": 50,
                },
            )
    except httpx.HTTPError as exc:
        raise Reject("GITHUB_UNAVAILABLE", "GitHub is unavailable. Try again shortly.") from exc
    if profile.status_code == 401:
        raise Reject("AUTH_REQUIRED", "GitHub authorization expired. Sign in again.")
    user = profile.json() if profile.status_code == 200 else {}
    repos = listing.json() if listing.status_code == 200 else []
    avatar = str(user.get("avatar_url") or "")
    return {
        "login": identity.login,
        "name": str(user.get("name") or identity.login),
        "avatar_url": avatar if avatar.startswith("https://avatars.githubusercontent.com/") else "",
        "repos": [
            {
                "full_name": str(r.get("full_name", "")),
                "description": str(r.get("description") or "")[:200],
                "language": str(r.get("language") or ""),
                "stars": int(r.get("stargazers_count") or 0),
                "pushed_at": str(r.get("pushed_at") or ""),
                "fork": bool(r.get("fork")),
            }
            for r in repos
            if isinstance(r, dict) and not r.get("private") and not r.get("archived")
        ],
    }


@router.get("/analyses/{job_id}/report.pdf")
def report_pdf(request: Request, job_id: str) -> Response:
    """The readiness report as a PDF, built from this scan's artifacts."""
    from quanta.core.pdf import render_pdf
    from quanta.core.report_data import build

    job = _job_or_404(request, job_id)

    def artifact(name: str) -> Any:
        try:
            return json.loads(_artifact(request, job, name))
        except Reject:
            return None

    score = artifact("score.json") or {}
    data = build(
        score=score,
        meta=artifact("meta.json") or {},
        readiness=artifact("readiness.json"),
        findings=(artifact("findings.json") or {}).get("findings", []),
        fixes=FixPlan.model_validate(artifact("fixes.json") or {}).public(),
    )
    name = str(score.get("provenance", {}).get("repo", "report")).replace("/", "-")
    return Response(
        content=render_pdf(data),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="quanta-{name}.pdf"'},
    )


@router.get("/standards")
def published_standards() -> dict[str, Any]:
    """The published rules the readiness assessment applies, each with its source."""
    data = standards()
    return {key: data[key] for key in ("checked", "sources", "frameworks", "milestones")}


@router.get("/analyses/{job_id}/readiness")
def readiness(request: Request, job_id: str) -> dict[str, Any]:
    """Post-quantum readiness of one analysis, with every source it applied."""
    job = _job_or_404(request, job_id)
    sources = {
        key: {k: v for k, v in value.items() if k in {"publisher", "date", "status", "url"}}
        for key, value in standards()["sources"].items()
    }
    try:
        result = json.loads(_artifact(request, job, "readiness.json"))
    except Reject:
        if job.status != "succeeded":
            raise
        # A cached corpus from before readiness.json existed has no assessment to show.
        result = None
    return {"readiness": result, "sources": sources}


@router.post("/analyses/{job_id}/review")
def review_fixes(request: Request, job_id: str, body: Selection) -> dict[str, Any]:
    # Reading a diff changes nothing; _plan enforces access (the sample is open to all).
    identity = auth(request).identity(request, required=False)
    if identity:
        auth(request).csrf(request, identity)
    result = review(_plan(request, job_id), body.selected)
    return {**result, "files": [{"path": f["path"], "diff": f["diff"]} for f in result["files"]]}


@router.post("/analyses/{job_id}/pull-request")
def pull_request(request: Request, job_id: str, body: PullRequest) -> dict[str, str]:
    identity = auth(request).identity(request)
    if identity is None:
        raise Reject("AUTH_REQUIRED")
    auth(request).csrf(request, identity)
    if not body.acknowledge_compatibility:
        raise Reject(
            "ACKNOWLEDGEMENT_REQUIRED",
            "Confirm the compatibility note before opening a pull request.",
        )
    registry = _registry(request)
    verification = pull_request_gate(registry, job_id, body.digest, body.acknowledge_verdict)
    plan = _plan(request, job_id)
    url = open_pull(
        registry, job_id, identity, plan, body.selected, body.digest, verification=verification
    )
    return {"url": url}


def pull_request_gate(
    registry: Any, job_id: str, digest: str, acknowledged: str | None
) -> dict[str, Any] | None:
    """PROTOCOL-R3 K1: a proposal becomes a pull request only after verification, when
    verification is available. ``regressed`` never proceeds; any other verdict short of
    ``verified`` proceeds only when the reviewer names it, and the PR body states it."""
    from quanta.web.review import latest_verification, verification_available

    record = latest_verification(registry, job_id, digest)
    if not verification_available(registry):
        return record if record and record["status"] == "done" else None
    if record is None or record["status"] in {"queued", "running"}:
        raise Reject(
            "VERIFICATION_REQUIRED",
            "Verify this selection with the project's tests before opening a pull request.",
        )
    verdict = record["verdict"] or "unverifiable"
    if verdict == "regressed":
        raise Reject(
            "VERIFICATION_FAILED",
            "The project's tests failed after this change. Deselect the failing changes.",
        )
    if verdict != "verified" and acknowledged != verdict:
        raise Reject(
            "ACKNOWLEDGEMENT_REQUIRED",
            f"The verdict is {verdict}. Confirm it to open a draft pull request anyway.",
        )
    return record


@lru_cache(maxsize=1)
def sample_outcome() -> AnalysisOutcome:
    # Deliberately weak source is data, never an importable application module.
    fixture = json.loads(asset_path("demo/product-sample.json").read_text())
    with TemporaryDirectory(prefix="quanta-sample-") as temporary:
        root = Path(temporary)
        for name, source in fixture.items():
            if not safe_path(name):
                raise Reject("INTERNAL", "Invalid bundled sample path.")
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source)
        return analyze_path(
            root,
            Provenance(
                repo="sample/clinic",
                commit_sha="0" * 40,
                analyzer_version=analyzer_version(),
                crypto_ruleset_version=CRYPTO_RULESET_VERSION,
            ),
        )


@router.post("/sample/replay", status_code=201)
def sample_replay(request: Request) -> JSONResponse:
    """Replay the recorded sample exactly as it streamed. No clone, no network."""
    service = auth(request)
    identity = service.identity(request, required=False)
    if identity:
        service.csrf(request, identity)
    _enforce_rate_limit(request)
    if not recorded_sample.available():
        raise Reject("REPO_NOT_FOUND", "The sample is not installed.")
    job = recorded_sample.start_replay(_registry(request))
    if identity:
        with _registry(request).db.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO analysis_access(job_id,user_id) VALUES(?,?) "
                "ON CONFLICT(job_id,user_id) DO NOTHING",
                (job.id, identity.user_id),
            )
    return JSONResponse(
        status_code=201,
        content={
            "job_id": job.id,
            "status": "running",
            "cached": True,
            "status_url": f"/api/v1/analyses/{job.id}",
            "events_url": f"/api/v1/analyses/{job.id}/events",
        },
    )


@router.get("/sample")
def sample() -> dict[str, Any]:
    """Everything the recorded sample run produced."""
    if not recorded_sample.available():
        raise Reject("REPO_NOT_FOUND", "The sample is not installed.")
    return recorded_sample.payload()


@router.post("/sample/review")
def sample_review(body: Selection) -> dict[str, Any]:
    result = review(recorded_sample.plan(), body.selected)
    return {
        **result,
        "sample": True,
        "files": [{"path": f["path"], "diff": f["diff"]} for f in result["files"]],
    }
