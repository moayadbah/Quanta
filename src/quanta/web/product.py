"""Product endpoints: private history, selected fixes and an honest interactive sample."""

from __future__ import annotations

import time
from functools import lru_cache
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from quanta.core.analyze import AnalysisOutcome, analyze_path
from quanta.core.fixes import FixPlan, review
from quanta.core.models import Provenance
from quanta.errors import Reject
from quanta.resources import asset_path
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version
from quanta.web.auth import auth
from quanta.web.db import timestamp
from quanta.web.pulls import open_pull
from quanta.web.routes import _artifact, _job_or_404, _registry

router = APIRouter()


class Selection(BaseModel):
    selected: list[str] = Field(min_length=1, max_length=200)


class PullRequest(Selection):
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")


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


@router.post("/analyses/{job_id}/review")
def review_fixes(request: Request, job_id: str, body: Selection) -> dict[str, Any]:
    identity = auth(request).identity(request, required=auth(request).settings.required)
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
    plan = _plan(request, job_id)
    url = open_pull(_registry(request), job_id, identity, plan, body.selected, body.digest)
    return {"url": url}


@lru_cache(maxsize=1)
def sample_outcome() -> AnalysisOutcome:
    return analyze_path(
        asset_path("demo/repos/product-sample"),
        Provenance(
            repo="sample/vault",
            commit_sha="0" * 40,
            analyzer_version=analyzer_version(),
            crypto_ruleset_version=CRYPTO_RULESET_VERSION,
        ),
    )


@router.get("/sample")
def sample() -> dict[str, Any]:
    outcome = sample_outcome()
    return {
        "sample": True,
        "repo": "sample/vault",
        "score": outcome.score.model_dump(mode="json"),
        "meta": outcome.meta.model_dump(mode="json"),
        "fixes": outcome.fixes.public(),
    }


@router.post("/sample/review")
def sample_review(body: Selection) -> dict[str, Any]:
    result = review(sample_outcome().fixes, body.selected)
    return {
        **result,
        "sample": True,
        "files": [{"path": f["path"], "diff": f["diff"]} for f in result["files"]],
    }
