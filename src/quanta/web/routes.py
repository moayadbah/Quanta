"""HTTP endpoints — the §5.2.2 contract, plus three demo additions.

Handlers perform **no analysis work** (§4.2). They validate, look up a job, and read a
file. Pydantic validation at the boundary is a security control rather than a
convenience: a malformed body is rejected with 422 before any application code runs.
"""

from __future__ import annotations

import time
from collections import defaultdict
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from quanta.config import get_settings
from quanta.core.ingest import parse_repo_url
from quanta.core.report import REPORT_SECURITY_HEADERS
from quanta.errors import Reject
from quanta.version import CRYPTO_RULESET_VERSION, __version__
from quanta.web import demo
from quanta.web import examples as examples_mod
from quanta.web.jobs import Job, JobRegistry
from quanta.web.sse import parse_last_event_id, stream
from quanta.web.store import ArtifactStore

router = APIRouter()


def _submissions(request: Request) -> dict[str, list[float]]:
    """Per-IP submission timestamps for the §8.1 rate limit.

    Held on ``app.state`` rather than in a module global. A global would be shared by
    every app instance in a process, which silently couples tests to one another — the
    eleventh request in a *test session* would be rate-limited regardless of which test
    made it. In-memory is otherwise right here: a single-node demo needs nothing more,
    and a shared store would be infrastructure added to replace a dict.
    """
    state = request.app.state
    if not hasattr(state, "submissions"):
        state.submissions = defaultdict(list)
    limiter: dict[str, list[float]] = state.submissions
    return limiter


class AnalysisRequest(BaseModel):
    """Boundary validation. The shape check happens here; the SSRF checks happen in
    :func:`quanta.core.ingest.parse_repo_url`, which runs before any network call."""

    repo_url: str = Field(min_length=1, max_length=2048)


def _registry(request: Request) -> JobRegistry:
    registry: JobRegistry = request.app.state.registry
    return registry


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _enforce_rate_limit(request: Request) -> None:
    cfg = get_settings().api
    limiter = _submissions(request)
    now = time.time()
    ip = _client_ip(request)

    recent = [t for t in limiter[ip] if now - t < 3600]
    limiter[ip] = recent
    if len(recent) >= cfg.rate_limit_per_ip_hour:
        raise Reject("RATE_LIMITED", f"limit is {cfg.rate_limit_per_ip_hour} submissions per hour")
    limiter[ip].append(now)


def _job_or_404(request: Request, job_id: str) -> Job:
    job = _registry(request).get(job_id)
    if job is None:
        raise Reject("REPO_NOT_FOUND", "no such analysis")
    return job


def _artifact(job: Job, name: str) -> Path:
    if job.status != "succeeded" or job.artifact_dir is None:
        raise Reject("NOT_FINISHED", f"analysis is {job.status}")
    path = ArtifactStore(job.artifact_dir.parent).path(job.id, name)
    if not path.is_file():
        raise Reject("NOT_FINISHED", f"{name} is not available")
    return path


# ---------------------------------------------------------------------------------------
# §5.2.2 contract
# ---------------------------------------------------------------------------------------


@router.post("/analyses", status_code=201)
def create_analysis(request: Request, body: AnalysisRequest) -> JSONResponse:
    """Submit a repository. Returns 201 with the URLs to follow it."""
    registry = _registry(request)
    cfg = get_settings().api

    if registry.active_count() >= cfg.max_queue_depth:
        raise Reject("RATE_LIMITED", "the queue is full; try again shortly")

    _enforce_rate_limit(request)

    # Validate before anything else happens. No DNS resolution has occurred at this point
    # — that ordering is the SSRF control (§7.3), not an implementation detail.
    parse_repo_url(body.repo_url)

    job = registry.submit(body.repo_url)
    return JSONResponse(
        status_code=200 if job.reused else 201,
        content={
            "job_id": job.id,
            "status": job.status,
            "status_url": f"/api/v1/analyses/{job.id}",
            "events_url": f"/api/v1/analyses/{job.id}/events",
        },
    )


@router.get("/analyses/{job_id}")
def get_analysis(request: Request, job_id: str) -> dict[str, Any]:
    registry = _registry(request)
    registry.drain()
    return _job_or_404(request, job_id).public()


@router.get("/analyses/{job_id}/events")
async def get_events(
    request: Request,
    job_id: str,
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
) -> StreamingResponse:
    """SSE progress. Reconnection resumes exactly, via ``Last-Event-ID`` (§5.2.3)."""
    job = _job_or_404(request, job_id)
    registry = _registry(request)

    delays = None
    if job.cached:
        delays = examples_mod.replay_delays(job.steps)

    return StreamingResponse(
        stream(job, registry, parse_last_event_id(last_event_id), delays),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Without this an intermediary may buffer the stream and defeat the point.
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/analyses/{job_id}/score")
def get_score(request: Request, job_id: str) -> Response:
    job = _job_or_404(request, job_id)
    return Response(
        content=_artifact(job, "score.json").read_text(encoding="utf-8"),
        media_type="application/json",
    )


@router.get("/analyses/{job_id}/report")
def get_report(request: Request, job_id: str) -> HTMLResponse:
    """The canonical Jinja2 report, served with its own hardened headers (§7.3 T5)."""
    job = _job_or_404(request, job_id)
    return HTMLResponse(
        content=_artifact(job, "report.html").read_text(encoding="utf-8"),
        headers=dict(REPORT_SECURITY_HEADERS),
    )


@router.get("/healthz")
def healthz(request: Request) -> dict[str, Any]:
    registry = _registry(request)
    return {
        "status": "ok",
        "version": __version__,
        "crypto_ruleset_version": CRYPTO_RULESET_VERSION,
        "queue_depth": registry.active_count(),
        "worker_heartbeat_age_s": registry.heartbeat_age(),
    }


# ---------------------------------------------------------------------------------------
# Demo additions
# ---------------------------------------------------------------------------------------


@router.get("/analyses/{job_id}/cdg")
def get_cdg(request: Request, job_id: str) -> Response:
    job = _job_or_404(request, job_id)
    return Response(
        content=_artifact(job, "cdg.json").read_text(encoding="utf-8"),
        media_type="application/json",
    )


@router.get("/analyses/{job_id}/trace")
def get_trace(request: Request, job_id: str) -> dict[str, Any]:
    """The pipeline trace: what each step did, and the evidence for it."""
    registry = _registry(request)
    registry.drain()
    job = _job_or_404(request, job_id)
    return {
        "job_id": job.id,
        "cached": job.cached,
        "steps": [s.model_dump(mode="json") for s in job.steps],
    }


@router.get("/analyses/{job_id}/meta")
def get_meta(request: Request, job_id: str) -> Response:
    job = _job_or_404(request, job_id)
    return Response(
        content=_artifact(job, "meta.json").read_text(encoding="utf-8"),
        media_type="application/json",
    )


@router.get("/content")
def get_content() -> dict[str, Any]:
    """Every user-facing walkthrough string, in both languages.

    Served as data so no sentence is hard-coded in the markup — which is what makes a
    missing translation a test failure rather than a blank panel during a presentation.
    """
    return demo.load_content()


@router.get("/glossary")
def get_glossary() -> dict[str, Any]:
    """Clickable term definitions: what it is, why we chose it, where it is defined."""
    return {"terms": demo.load_glossary()}


@router.get("/demo/variants")
def get_demo_variants() -> dict[str, Any]:
    """The three vault variants, measured by the real analyzer at request time."""
    return demo.variant_report()


@router.get("/demo/xwing")
def get_xwing_evidence() -> dict[str, Any]:
    """The ADR-019 comparison, recomputed live against the published draft-10 vector."""
    return demo.xwing_evidence()


@router.get("/examples")
def list_examples() -> dict[str, Any]:
    """Pre-computed runs (ADR-022), always flagged ``cached``."""
    return {"examples": [e.public() for e in examples_mod.load_examples()]}


@router.post("/examples/{slug}/replay", status_code=201)
def replay_example(request: Request, slug: str) -> JSONResponse:
    example = examples_mod.find_example(slug)
    if example is None:
        raise Reject("REPO_NOT_FOUND", "no such example")

    job = examples_mod.start_replay(example, _registry(request))
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


@router.get("/about")
def about() -> dict[str, Any]:
    """What the tool measures, and — as important — what it does not claim (§1.4).

    Served as data so the UI cannot drift from the documented scope.
    """
    return {
        "version": __version__,
        "crypto_ruleset_version": CRYPTO_RULESET_VERSION,
        "measures": [
            "How many cryptographic call sites exist, and where",
            "Whether an insulation layer fronts them (NIST CSWP 39)",
            "Whether the algorithm is configuration-driven or hard-coded",
            "How far a change would propagate through the module graph",
        ],
        "does_not_claim": [
            "Not a migration-cost estimate — real cost is dominated by certificates, "
            "protocols, hardware and compliance, all out of scope",
            "Not a cryptographic security review",
            "Not a code execution service — your repository is parsed, never run",
            "Python only",
        ],
        "guarantees": [
            "No repository code is imported, executed or installed at any point",
            "The clone is deleted unconditionally, including on failure and timeout",
            "Every deduction cites a file and line",
            "The same commit yields byte-identical cdg.json and score.json",
        ],
    }
