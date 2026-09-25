"""The report and the PDF, rendered from a run's data on every request.

The web app never serves the HTML an engine wrote at scan time: a run made by any engine,
old or new, is read through ``core/legacy.normalise`` (today's rules, nothing unmeasured
read as clean) and drawn with today's template, in the reader's language. The same reading
feeds the workspace's Findings and Changes, so a patch the current rules refuse can never
be offered for review or a pull request either.
"""

from __future__ import annotations

import base64
import json
from collections import OrderedDict
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response

from quanta.core.fixes import FixPlan
from quanta.core.legacy import RunData, normalise
from quanta.core.report import REPORT_SECURITY_HEADERS, render_data
from quanta.core.report_data import LANGUAGES, build
from quanta.errors import Reject
from quanta.web import sample as recorded_sample
from quanta.web.auth import Identity, auth, github_client
from quanta.web.jobs import Job
from quanta.web.routes import _artifact, _job_or_404

router = APIRouter()

#: Finished runs never change, so their reading is kept for a few requests.
_READINGS: OrderedDict[str, tuple[dict[str, Any], dict[str, Any], RunData]] = OrderedDict()
_READINGS_MAX = 32
AVATAR_HOST = "https://avatars.githubusercontent.com/"


def _json(request: Request, job: Job, name: str) -> Any:
    try:
        return json.loads(_artifact(request, job, name))
    except Reject:
        return None


def read_run(request: Request, job: Job) -> tuple[dict[str, Any], dict[str, Any], RunData]:
    """Score, meta and the normalised run (findings, plan, readiness) of a finished job."""
    if job.status == "succeeded" and job.id in _READINGS:
        _READINGS.move_to_end(job.id)
        return _READINGS[job.id]
    score = _json(request, job, "score.json") or {}
    meta = _json(request, job, "meta.json") or {}
    findings = _json(request, job, "findings.json")
    plan = FixPlan.model_validate(_json(request, job, "fixes.json") or {})
    data = normalise(
        score=score,
        readiness=_json(request, job, "readiness.json"),
        findings=findings.get("findings", []) if isinstance(findings, dict) else None,
        plan=plan,
        cdg=_json(request, job, "cdg.json") if findings is None else None,
    )
    reading = (score, meta, data)
    if job.status == "succeeded":
        _READINGS[job.id] = reading
        while len(_READINGS) > _READINGS_MAX:
            _READINGS.popitem(last=False)
    return reading


def language(request: Request) -> str:
    wanted = request.query_params.get("lang") or request.cookies.get("quanta-language") or "en"
    return wanted if wanted in LANGUAGES else "en"


def _avatar(url: str) -> bytes | None:
    if not url.startswith(AVATAR_HOST):
        return None
    try:
        with httpx.Client(timeout=3, follow_redirects=False) as client:
            reply = client.get(url + ("&" if "?" in url else "?") + "s=128")
        if reply.status_code == 200 and reply.headers.get("content-type", "").startswith("image/"):
            return reply.content[:500_000]
    except httpx.HTTPError:
        return None
    return None


def run_info(request: Request, job: Job, identity: Identity | None) -> dict[str, Any]:
    """Who ran the scan and when: the signed-in account, the sample, or a local run."""
    created = job.created_at
    from datetime import UTC, datetime

    at = datetime.fromtimestamp(created, UTC).isoformat() if created else ""
    if job.cached and recorded_sample.available():
        manifest = recorded_sample.manifest()
        if job.repo_url.lower().endswith("/" + str(manifest.get("repo", "")).lower()):
            return {"kind": "sample", "at": manifest.get("recorded_at", at)}
    if identity is None:
        return {"kind": "local", "at": at}
    with auth(request).db.connect() as conn:
        row = conn.execute(
            "SELECT requested_at FROM scan_requests WHERE job_id=? AND user_id=?",
            (job.id, identity.user_id),
        ).fetchone()
    info: dict[str, Any] = {
        "kind": "user",
        "login": identity.login,
        "name": identity.login,
        "at": row[0] if row else at,
    }
    try:
        with github_client(identity.token) as client:
            reply = client.get("/user")
        if reply.status_code == 200:
            profile = reply.json()
            info["name"] = str(profile.get("name") or identity.login)[:80]
            info["avatar_url"] = str(profile.get("avatar_url") or "")
    except (httpx.HTTPError, ValueError):
        pass
    avatar = _avatar(info.get("avatar_url", ""))
    if avatar:
        info["avatar_bytes"] = avatar
        info["avatar_data"] = "data:image/png;base64," + base64.b64encode(avatar).decode()
    return info


def report_data(request: Request, job: Job, lang: str, *, absolute: bool = False) -> dict[str, Any]:
    from quanta.web.assets import asset_url

    service = auth(request)
    identity = service.identity(request, required=False)
    score, meta, run = read_run(request, job)
    repo = str((score.get("provenance") or {}).get("repo", ""))
    rescan = (
        f"/workspace.html#rescan={repo}" if "/" in repo and not repo.startswith("local:") else ""
    )
    if rescan and absolute:
        base = service.settings.public_url.rstrip("/") or str(request.base_url).rstrip("/")
        rescan = base + rescan
    return build(
        score=score,
        meta=meta,
        readiness=run.readiness,
        findings=run.findings,
        fixes=run.plan.public(),
        lang=lang,
        assessed=run.assessed,
        roles_measured=run.roles_measured,
        older_engine=run.older_engine,
        run=run_info(request, job, identity),
        rescan_url=rescan if (not run.assessed or run.older_engine) else "",
        font_base=asset_url("brand/fonts/"),
    )


@router.get("/analyses/{job_id}/report")
def report_html(request: Request, job_id: str) -> HTMLResponse:
    """The report, drawn now from the run's data (§7.3 T5 headers)."""
    job = _job_or_404(request, job_id)
    if job.status != "succeeded":
        raise Reject("NOT_FINISHED", f"analysis is {job.status}")
    data = report_data(request, job, language(request))
    return HTMLResponse(content=render_data(data), headers=dict(REPORT_SECURITY_HEADERS))


@router.get("/analyses/{job_id}/report.pdf")
def report_pdf(request: Request, job_id: str) -> Response:
    """The same report as a PDF, A4 by default (``?paper=letter``)."""
    from quanta.core.pdf import render_pdf

    job = _job_or_404(request, job_id)
    if job.status != "succeeded":
        raise Reject("NOT_FINISHED", f"analysis is {job.status}")
    lang = language(request)
    data = report_data(request, job, lang, absolute=True)
    paper = "letter" if request.query_params.get("paper") == "letter" else "a4"
    name = str(data["repo"] or "report").replace("/", "-").replace(":", "-")
    suffix = "-ar" if lang == "ar" else ""
    return Response(
        content=render_pdf(data, paper),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="quanta-{name}{suffix}.pdf"'},
    )
