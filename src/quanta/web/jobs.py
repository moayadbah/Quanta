"""In-memory job registry backed by a process pool (ADR-021).

**This is a documented deviation.** §3.5 and ADR-006 specify a SQLite ``jobs`` table
polled by a separate worker process, and this module satisfies neither DoD-W2 nor M8's
"worker process" clause: jobs are lost on API restart, and there is no staleness sweep.
That trade was made deliberately for a demo build; see ``docs/adr/ADR-021``.

Two things are preserved so the deviation stays cheap to undo:

* The **API contract** (§5.2.2) and the event format are exactly what a durable worker
  would produce, so upgrading means replacing this module, not the tier around it.
* Analysis runs in a **child process**, not a thread. §3.5's objection to
  ``BackgroundTasks`` is real and technical — CPU-bound parsing starves the ASGI event
  loop — and it applies just as much to a thread pool, because the LibCST visitor holds
  the GIL. Live progress is the whole point of the demo, so it must not stutter.

Each job gets its **own** spawned process rather than a pooled worker. That is not an
arbitrary choice:

* A ``multiprocessing.Queue`` cannot be pickled into a ``ProcessPoolExecutor`` task —
  ``Queue objects should only be shared between processes through inheritance``. Passing
  one to ``Process(args=…)`` is the supported path.
* §4.2 describes a per-job analyzer child that can carry its own ``setrlimit`` caps and be
  killed on a watchdog timeout. A pooled worker is reused across jobs, which is
  incompatible with both.

Progress crosses the process boundary on that queue and is drained into per-job buffers
that SSE replays from.
"""

from __future__ import annotations

import multiprocessing as mp
import queue
import time
import uuid
from dataclasses import dataclass, field
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import Any, Literal

from quanta.config import get_settings
from quanta.core.analyze import STEP_TITLES, analyze_repository, write_artifacts
from quanta.core.models import StepRecord
from quanta.errors import Reject

JobStatus = Literal["queued", "running", "succeeded", "failed"]


@dataclass
class JobEvent:
    """One SSE-shaped event. ``id`` doubles as the ``Last-Event-ID`` cursor (§5.2.3)."""

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
    events: list[JobEvent] = field(default_factory=list)
    steps: list[StepRecord] = field(default_factory=list)

    def add_event(self, event: str, data: dict[str, Any]) -> JobEvent:
        record = JobEvent(id=len(self.events) + 1, event=event, data=data)
        self.events.append(record)
        return record

    @property
    def phase(self) -> str | None:
        return self.steps[-1].id if self.steps else None

    @property
    def progress(self) -> int:
        done = sum(1 for s in self.steps if s.status in {"done", "skipped"})
        return int(100 * done / len(STEP_TITLES))

    def public(self) -> dict[str, Any]:
        """The §5.2.2 status payload."""
        body: dict[str, Any] = {
            "job_id": self.id,
            "status": self.status,
            "phase": self.phase,
            "progress": self.progress,
            "cached": self.cached,
        }
        if self.agility_score is not None:
            body["agility_score"] = self.agility_score
        if self.status == "succeeded":
            body["report_url"] = f"/api/v1/analyses/{self.id}/report"
        if self.error_code:
            body["error_code"] = self.error_code
            body["detail"] = self.error_detail
        return body


# ---------------------------------------------------------------------------------------
# Child process entry point
# ---------------------------------------------------------------------------------------


def _run_analysis(repo_url: str, out_dir: str, progress_queue: Any) -> None:
    """Entry point of the analyzer child process.

    Must be importable at module level so ``spawn`` can re-import it. Everything travels
    back over the queue — the artifacts themselves go via the filesystem, so only small
    JSON-safe values cross the boundary.
    """

    def emit(step: StepRecord) -> None:
        progress_queue.put(("step", step.model_dump(mode="json")))

    try:
        outcome = analyze_repository(repo_url, get_settings(), emit)
    except Reject as exc:
        progress_queue.put(("result", {"ok": False, "error_code": exc.code, "detail": exc.detail}))
        return
    except Exception as exc:  # pragma: no cover - defensive
        # A traceback must never reach a client (§5.2.4); the type name is enough to triage.
        progress_queue.put(
            ("result", {"ok": False, "error_code": "INTERNAL", "detail": type(exc).__name__})
        )
        return

    write_artifacts(outcome, Path(out_dir))
    progress_queue.put(
        (
            "result",
            {
                "ok": True,
                "agility_score": outcome.score.agility_score,
                "repo": outcome.score.provenance.repo,
                "commit_sha": outcome.score.provenance.commit_sha,
            },
        )
    )


# ---------------------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------------------


class JobRegistry:
    """Holds jobs in memory and runs each analysis in a pooled child process."""

    def __init__(self, artifact_root: Path) -> None:
        self.artifact_root = artifact_root
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, Job] = {}
        # `spawn` rather than `fork`: forking an event-loop process inherits loop state
        # and file descriptors, and is unsafe on macOS alongside threads.
        self._ctx = mp.get_context("spawn")
        self._queues: dict[str, Any] = {}
        self._procs: dict[str, BaseProcess] = {}

    # -- lifecycle -----------------------------------------------------------------

    def shutdown(self) -> None:
        for proc in self._procs.values():
            if proc.is_alive():
                proc.terminate()

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def active_count(self) -> int:
        return sum(1 for j in self._jobs.values() if j.status in {"queued", "running"})

    # -- submission ----------------------------------------------------------------

    def submit(self, repo_url: str) -> Job:
        """Create a job and start it. The id is a UUIDv4 capability (§7.3)."""
        job = Job(id=str(uuid.uuid4()), repo_url=repo_url)
        job.artifact_dir = self.artifact_root / job.id
        self._jobs[job.id] = job

        progress_queue = self._ctx.Queue()
        self._queues[job.id] = progress_queue

        job.status = "running"
        job.add_event("status", {"status": "running"})
        # Seed the full step list so the UI can render the pipeline before it starts,
        # which is what makes the demo legible rather than a spinner.
        job.add_event(
            "plan",
            {"steps": [{"id": sid, "title": title} for sid, title in STEP_TITLES]},
        )

        proc = self._ctx.Process(
            target=_run_analysis,
            args=(repo_url, str(job.artifact_dir), progress_queue),
            daemon=True,
        )
        proc.start()
        self._procs[job.id] = proc
        return job

    def adopt_cached(self, job: Job) -> None:
        """Register a pre-computed job (the cached demo corpus, ADR-022)."""
        self._jobs[job.id] = job

    # -- progress ------------------------------------------------------------------

    def drain(self) -> None:
        """Move any queued child-process messages into job state. Called by the SSE loop."""
        for job_id, q in list(self._queues.items()):
            job = self._jobs.get(job_id)
            if job is None:
                continue
            while True:
                try:
                    kind, payload = q.get_nowait()
                except (queue.Empty, OSError, EOFError, ValueError):
                    break
                if kind == "step":
                    self._apply_step(job, payload)
                elif kind == "result":
                    self._finish(job, payload)

            self._check_liveness(job_id, job)

    def _check_liveness(self, job_id: str, job: Job) -> None:
        """Catch a child that died without reporting — an OOM kill, or a hard crash.

        Without this the client waits on a stream that will never produce a terminal
        event, which is the worst possible failure mode for a demo.
        """
        if job.status != "running":
            return
        proc = self._procs.get(job_id)
        if proc is None or proc.is_alive():
            if (
                proc is not None
                and time.time() - job.created_at > get_settings().analysis.max_job_seconds
            ):
                proc.terminate()
                self._finish(
                    job,
                    {
                        "ok": False,
                        "error_code": "ANALYSIS_TIMEOUT",
                        "detail": "exceeded the job time limit",
                    },
                )
            return
        self._finish(
            job,
            {
                "ok": False,
                "error_code": "INTERNAL",
                "detail": f"analyzer process exited unexpectedly (code {proc.exitcode})",
            },
        )

    def _apply_step(self, job: Job, payload: dict[str, Any]) -> None:
        record = StepRecord.model_validate(payload)
        for i, existing in enumerate(job.steps):
            if existing.id == record.id:
                job.steps[i] = record
                break
        else:
            job.steps.append(record)
        job.add_event("step", payload)

    def _finish(self, job: Job, result: dict[str, Any]) -> None:
        """Apply a terminal result exactly once and emit the closing SSE event."""
        if job.status in {"succeeded", "failed"}:
            return

        if result.get("ok"):
            job.status = "succeeded"
            job.agility_score = result.get("agility_score")
            job.add_event(
                "done",
                {
                    "status": "succeeded",
                    "agility_score": job.agility_score,
                    "report_url": f"/api/v1/analyses/{job.id}/report",
                },
            )
        else:
            job.status = "failed"
            job.error_code = result.get("error_code", "INTERNAL")
            job.error_detail = result.get("detail")
            job.add_event("failed", {"error_code": job.error_code, "detail": job.error_detail})

        job.finished_at = time.time()
        self._queues.pop(job.id, None)
        proc = self._procs.pop(job.id, None)
        if proc is not None and proc.is_alive():
            proc.join(timeout=1)
