"""The one sample on the workspace: a real public repository, recorded once through the
real pipeline, replayed exactly as it streamed (round five).

``scripts/record_sample.py`` runs ``analyze_repository`` on the pinned repository, keeps
every artifact it wrote, and records every event the run emitted with its time offset
(``at_ms``). A replay registers a cached job carrying those events; the SSE stream paces
them by their recorded offsets, compressed into a short window. Nothing is recomputed, so
the sample shows exactly what a live scan of that commit showed.
"""

from __future__ import annotations

import json
import time
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any

from quanta.core.fixes import FixPlan
from quanta.core.ingest import parse_repo_url
from quanta.resources import asset_path
from quanta.version import analyzer_version
from quanta.web.db import timestamp
from quanta.web.jobs import Job, JobRegistry

SAMPLE_DIR = asset_path("demo/sample")


def _read(name: str) -> Any:
    return json.loads((SAMPLE_DIR / name).read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def manifest() -> dict[str, Any]:
    data: dict[str, Any] = _read("sample.json")
    return data


@lru_cache(maxsize=1)
def plan() -> FixPlan:
    return FixPlan.model_validate_json((SAMPLE_DIR / "fixes.json").read_text(encoding="utf-8"))


def payload() -> dict[str, Any]:
    """Everything the recorded run produced, for the home page and the workspace."""
    return {
        "sample": True,
        "repo": manifest()["repo"],
        "commit_sha": manifest()["commit_sha"],
        "recorded_at": manifest()["recorded_at"],
        "findings": _read("findings.json")["findings"],
        "score": _read("score.json"),
        "meta": _read("meta.json"),
        "fixes": plan().public(),
        "readiness": _read("readiness.json"),
    }


#: One stored replay serves every visitor for a day: each stream keeps its own cursor, so
#: sharing the job costs nothing, and the hosted database does not grow with every click.
REUSE_SECONDS = 86_400


def _recent(registry: JobRegistry) -> Job | None:
    owner, name = parse_repo_url(f"https://github.com/{manifest()['repo']}")
    with registry.db.connect() as conn:
        row = conn.execute(
            "SELECT id FROM jobs WHERE cached=1 AND repo_owner=? AND repo_name=? "
            "AND analyzer_version=? AND created_at>? ORDER BY created_at DESC LIMIT 1",
            (owner, name, analyzer_version(), timestamp(time.time() - REUSE_SECONDS)),
        ).fetchone()
    if row is None or not registry.store.complete(row[0]):
        return None
    return registry.get(row[0])


def start_replay(registry: JobRegistry) -> Job:
    """A cached job holding the recorded events, in order, with their offsets."""
    recent = _recent(registry)
    if recent is not None:
        return recent
    info = manifest()
    job = Job(id=str(uuid.uuid4()), repo_url=f"https://github.com/{info['repo']}")
    job.cached = True
    job.artifact_dir = SAMPLE_DIR
    job.status = "succeeded"
    job.finished_at = time.time()
    score = _read("score.json")
    job.agility_score = score.get("agility_score")
    for event in _read("events.json")["events"]:
        data = dict(event["data"])
        data["at_ms"] = event["at_ms"]
        if event["event"] == "status":
            data["cached"] = True
        if event["event"] == "done":
            data.update({"cached": True, "report_url": f"/api/v1/analyses/{job.id}/report"})
        job.add_event(event["event"], data)
    registry.adopt_cached(job)
    return job


def available() -> bool:
    return (SAMPLE_DIR / "sample.json").is_file() and (SAMPLE_DIR / "events.json").is_file()


def recording_files() -> list[Path]:
    return sorted(p for p in SAMPLE_DIR.iterdir() if p.is_file())
