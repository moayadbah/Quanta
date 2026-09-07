"""Cached demo corpus (ADR-022).

Unauthenticated GitHub allows 60 API requests per hour and presentation wifi fails at the
worst possible moment. Pre-computed artifacts make the demo deterministic, instant and
offline — which also makes it *reproducible*, since every viewer sees the same numbers
from the same pinned commits.

Cached runs are marked ``cached: true`` everywhere they surface, and the UI badges them.
Passing off a replay as a live analysis would be the kind of quiet overclaim §1.4 exists
to prevent.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from quanta.core.models import StepRecord
from quanta.resources import asset_path
from quanta.web.jobs import Job, JobRegistry

CORPUS_ROOT = asset_path("demo/corpus")

#: Replay pacing. Real analyses take tens of seconds, most of it clone and parse. Replaying
#: at true speed would waste a presentation; replaying instantly would hide the pipeline
#: the demo exists to show. Durations are scaled and clamped into a watchable band.
_REPLAY_SCALE = 0.08
_REPLAY_MIN_MS = 380
_REPLAY_MAX_MS = 1100


@dataclass(frozen=True)
class Example:
    slug: str
    repo: str
    title: str
    blurb: str
    blurb_ar: str
    agility_score: float
    sites: int
    directory: Path

    def public(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "repo": self.repo,
            "title": self.title,
            "blurb": self.blurb,
            "blurb_ar": self.blurb_ar,
            "agility_score": self.agility_score,
            "sites": self.sites,
            "cached": True,
        }


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        payload: dict[str, Any] = json.load(fh)
    return payload


def load_examples() -> list[Example]:
    """Discover cached examples. Returns an empty list when the corpus is absent."""
    if not CORPUS_ROOT.is_dir():
        return []

    examples: list[Example] = []
    for directory in sorted(CORPUS_ROOT.iterdir()):
        manifest = directory / "example.json"
        score_path = directory / "score.json"
        if not (manifest.is_file() and score_path.is_file()):
            continue
        meta = _read_json(manifest)
        score = _read_json(score_path)
        examples.append(
            Example(
                slug=directory.name,
                repo=str(score["provenance"]["repo"]),
                title=str(meta.get("title", directory.name)),
                blurb=str(meta.get("blurb", "")),
                blurb_ar=str(meta.get("blurb_ar", "")),
                agility_score=float(score["agility_score"]),
                sites=int(meta.get("sites", 0)),
                directory=directory,
            )
        )
    return examples


def find_example(slug: str) -> Example | None:
    return next((e for e in load_examples() if e.slug == slug), None)


def replay_delays(steps: list[StepRecord]) -> list[int]:
    """Scaled per-step delays, in milliseconds."""
    return [
        max(_REPLAY_MIN_MS, min(_REPLAY_MAX_MS, int(step.duration_ms * _REPLAY_SCALE)))
        for step in steps
    ]


def start_replay(example: Example, registry: JobRegistry) -> Job:
    """Register a cached run as a job whose events are already complete.

    The job is created fully populated; the SSE endpoint paces delivery. That keeps
    replay logic in one place and means a cached run and a live run are indistinguishable
    to the client apart from the ``cached`` flag.
    """
    meta = _read_json(example.directory / "meta.json")
    score = _read_json(example.directory / "score.json")
    steps = [StepRecord.model_validate(s) for s in meta.get("steps", [])]

    job = Job(id=str(uuid.uuid4()), repo_url=f"https://github.com/{example.repo}")
    job.cached = True
    job.artifact_dir = example.directory
    job.steps = steps
    job.status = "succeeded"
    job.agility_score = float(score["agility_score"])
    job.finished_at = time.time()

    job.add_event("status", {"status": "running", "cached": True})
    job.add_event(
        "plan",
        {"steps": [{"id": s.id, "title": s.title} for s in steps]},
    )
    for step in steps:
        job.add_event("step", step.model_dump(mode="json"))
    job.add_event(
        "done",
        {
            "status": "succeeded",
            "agility_score": job.agility_score,
            "report_url": f"/api/v1/analyses/{job.id}/report",
            "cached": True,
        },
    )

    registry.adopt_cached(job)
    return job
