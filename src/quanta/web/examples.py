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
    """A cached run. Its title and description live in the content file, by slug."""

    slug: str
    repo: str
    commit_sha: str
    status: str
    agility_score: float | None
    sites: int
    findings: int
    proposals: int
    refusals: int
    directory: Path

    def public(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "repo": self.repo,
            "commit_sha": self.commit_sha,
            "status": self.status,
            "agility_score": self.agility_score,
            "sites": self.sites,
            "findings": self.findings,
            "proposals": self.proposals,
            "refusals": self.refusals,
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
        raw_score = score.get("agility_score")
        examples.append(
            Example(
                slug=directory.name,
                repo=str(score["provenance"]["repo"]),
                commit_sha=str(score["provenance"]["commit_sha"]),
                status=str(score.get("status", "scored")),
                agility_score=None if raw_score is None else float(raw_score),
                sites=int(meta.get("sites", 0)),
                findings=int(meta.get("findings", 0)),
                proposals=int(meta.get("proposals", 0)),
                refusals=int(meta.get("refusals", 0)),
                directory=directory,
            )
        )
    return examples


def find_example(slug: str) -> Example | None:
    return next((e for e in load_examples() if e.slug == slug), None)


def recorded_steps(example: Example) -> list[dict[str, Any]]:
    """Step ids, outcomes and measured durations, with each step's start offset."""
    meta = _read_json(example.directory / "meta.json")
    offset = 0
    steps = []
    for raw in meta.get("steps", []):
        step = StepRecord.model_validate(raw)
        steps.append(
            {
                "id": step.id,
                "status": step.status,
                "start_ms": offset,
                "duration_ms": step.duration_ms,
            }
        )
        offset += step.duration_ms
    return steps


def first_refusal(example: Example) -> dict[str, Any] | None:
    """One place Quanta refused to change, with the source line, for the landing page."""
    path = example.directory / "fixes.json"
    if not path.is_file():
        return None
    skipped = _read_json(path).get("skipped", [])
    if not skipped:
        return None
    first = skipped[0]
    snippet = ""
    findings = example.directory / "findings.json"
    if findings.is_file():
        for item in _read_json(findings).get("findings", []):
            if item["file"] == first["path"] and item["line"] == first["line"]:
                snippet = str(item.get("snippet", ""))
                break
    return {"path": first["path"], "line": first["line"], "code": first["code"], "snippet": snippet}


def replay_delays(steps: list[StepRecord]) -> list[int]:
    """Scaled per-step delays, in milliseconds."""
    return [
        max(_REPLAY_MIN_MS, min(_REPLAY_MAX_MS, int(step.duration_ms * _REPLAY_SCALE)))
        for step in steps
    ]


def _finding_batches(directory: Path) -> list[dict[str, Any]]:
    path = directory / "findings.json"
    if not path.is_file():
        return []
    batches: dict[str, list[dict[str, Any]]] = {}
    for item in _read_json(path).get("findings", []):
        batches.setdefault(str(item["file"]), []).append(item)
    return [{"file": file, "items": items} for file, items in batches.items()]


def _proposal_batches(directory: Path) -> list[dict[str, Any]]:
    path = directory / "fixes.json"
    if not path.is_file():
        return []
    from quanta.core.analyze import proposal_payload
    from quanta.core.fixes import FixPlan

    plan = FixPlan.model_validate_json(path.read_text(encoding="utf-8"))
    return [proposal_payload(file) for file in plan.files if file.changes]


def start_replay(example: Example, registry: JobRegistry) -> Job:
    """Register a cached run as a job whose events are already complete.

    The job is created fully populated; the SSE endpoint paces delivery. That keeps
    replay logic in one place and means a cached run and a live run are indistinguishable
    to the client apart from the ``cached`` flag.
    """
    meta = _read_json(example.directory / "meta.json")
    steps = [StepRecord.model_validate(s) for s in meta.get("steps", [])]

    job = Job(id=str(uuid.uuid4()), repo_url=f"https://github.com/{example.repo}")
    job.cached = True
    job.artifact_dir = example.directory
    job.steps = steps
    job.status = "succeeded"
    job.agility_score = example.agility_score
    job.finished_at = time.time()

    job.add_event("status", {"status": "running", "cached": True})
    job.add_event(
        "plan",
        {"steps": [{"id": s.id, "title": s.title} for s in steps]},
    )
    for step in steps:
        if step.id == "parse":
            # Replay the evidence in the order a live run produces it: the parse step
            # starts, each file's findings arrive, then the step closes.
            job.add_event("step", {**step.model_dump(mode="json"), "status": "running"})
            for batch in _finding_batches(example.directory):
                job.add_event("findings", batch)
        job.add_event("step", step.model_dump(mode="json"))
    for proposal in _proposal_batches(example.directory):
        job.add_event("proposals", proposal)
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
