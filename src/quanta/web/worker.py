"""Independent worker supervisor with durable leases and a per-job watchdog."""

from __future__ import annotations

import multiprocessing as mp
import os
import queue
import signal
import time
from dataclasses import dataclass
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import Any

from quanta.config import Settings, get_settings
from quanta.core.analyze import STEP_TITLES, analyze_repository, write_artifacts
from quanta.core.ingest import RepoMetadata, remove_tree
from quanta.core.models import Provenance, StepRecord
from quanta.errors import Reject
from quanta.version import CRYPTO_RULESET_VERSION
from quanta.web.db import event, timestamp
from quanta.web.jobs import JobRegistry
from quanta.web.sandbox import block_network, prepare
from quanta.web.store import ARTIFACT_NAMES


@dataclass
class Running:
    row: dict[str, Any]
    process: BaseProcess
    messages: Any
    started: float
    scratch: Path


def analyze_child(row: dict[str, Any], scratch: str, cfg: Settings, messages: Any) -> None:
    def emit(step: StepRecord) -> None:
        messages.put(("step", step.model_dump(mode="json")))

    try:
        prepare(cfg)
        root = Path(scratch)
        metadata = RepoMetadata(
            owner=row["repo_owner"],
            name=row["repo_name"],
            commit_sha=row["commit_sha"],
            default_branch=row["default_branch"],
            size_kb=row["size_kb"],
        )
        outcome = analyze_repository(
            f"https://github.com/{metadata.slug}",
            cfg,
            emit,
            metadata=metadata,
            scratch_parent=root,
            after_clone=lambda: block_network(required=cfg.require_sandbox),
        )
        write_artifacts(outcome, root / "output")
        messages.put(
            (
                "result",
                {
                    "ok": True,
                    "agility_score": outcome.score.agility_score,
                    "truncated": outcome.score.coverage.truncated,
                },
            )
        )
    except Reject as exc:
        messages.put(("result", {"ok": False, "error_code": exc.code, "detail": exc.detail}))
    except Exception:
        messages.put(
            (
                "result",
                {
                    "ok": False,
                    "error_code": "INTERNAL",
                    "detail": "The analyzer could not complete this repository.",
                },
            )
        )


class Worker:
    def __init__(self, registry: JobRegistry, worker_id: str, scratch_root: Path) -> None:
        self.registry = registry
        self.cfg = registry.settings
        self.worker_id = worker_id
        self.scratch_root = scratch_root.resolve()
        self.scratch_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.running: dict[str, Running] = {}
        self.context = mp.get_context("spawn")

    def claim(self) -> dict[str, Any] | None:
        with self.registry.db.connect(write=True) as conn:
            row = conn.execute(
                "UPDATE jobs SET status='running',worker_id=?,claimed_at=?,attempts=attempts+1 "
                "WHERE id=(SELECT id FROM jobs WHERE status='queued' AND attempts<? "
                "ORDER BY created_at,id LIMIT 1) "
                "AND (SELECT COUNT(*) FROM jobs WHERE status='running')<? "
                "RETURNING *",
                (
                    self.worker_id,
                    timestamp(),
                    self.cfg.worker.max_attempts,
                    self.cfg.worker.concurrency,
                ),
            ).fetchone()
            if row is None:
                return None
            event(conn, row["id"], "status", {"status": "running", "attempt": row["attempts"]})
            event(
                conn,
                row["id"],
                "plan",
                {
                    "steps": [{"id": sid, "title": title} for sid, title in STEP_TITLES],
                },
            )
            return dict(row)

    def heartbeat(self) -> set[str]:
        lost = set()
        with self.registry.db.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO worker_heartbeats(id,last_seen) VALUES(?,?) "
                "ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen",
                (self.worker_id, timestamp()),
            )
            for run in self.running.values():
                changed = conn.execute(
                    "UPDATE jobs SET claimed_at=? WHERE id=? AND worker_id=? "
                    "AND attempts=? AND status='running'",
                    (timestamp(), run.row["id"], self.worker_id, run.row["attempts"]),
                ).rowcount
                if not changed:
                    lost.add(run.row["id"])
        return lost

    def scratch_for(self, row: dict[str, Any]) -> Path:
        # All ids originated as validated UUIDv4s in the registry.
        self.registry.store.directory(row["id"])
        return self.scratch_root / f"{row['id']}-{int(row['attempts'])}"

    def sweep(self, now: float | None = None) -> None:
        instant = time.time() if now is None else now
        clean: list[Path] = []
        artifacts: list[str] = []
        with self.registry.db.connect(write=True) as conn:
            stale = conn.execute(
                "SELECT * FROM jobs WHERE status='running' AND claimed_at<?",
                (timestamp(instant - self.cfg.worker.claim_ttl_s),),
            ).fetchall()
            for row in stale:
                clean.append(self.scratch_for(dict(row)))
                exhausted = row["attempts"] >= self.cfg.worker.max_attempts
                status = "failed" if exhausted else "queued"
                conn.execute(
                    "UPDATE jobs SET status=?,worker_id=NULL,claimed_at=NULL,phase=NULL,"
                    "finished_at=?,error_code=? WHERE id=?",
                    (
                        status,
                        timestamp(instant) if exhausted else None,
                        "INTERNAL" if exhausted else None,
                        row["id"],
                    ),
                )
                event(
                    conn,
                    row["id"],
                    "error" if exhausted else "status",
                    {
                        "status": status,
                        "error_code": "INTERNAL" if exhausted else None,
                        "detail": "Worker lease expired; retry limit reached."
                        if exhausted
                        else "Worker lease expired; analysis requeued.",
                    },
                )
            expired = conn.execute(
                "SELECT id FROM jobs WHERE status IN ('succeeded','failed','timeout') "
                "AND finished_at<?",
                (timestamp(instant - self.cfg.retention.artifact_ttl_days * 86400),),
            ).fetchall()
            for row in expired:
                artifacts.append(row["id"])
                conn.execute("DELETE FROM jobs WHERE id=?", (row["id"],))
            conn.execute(
                "DELETE FROM worker_heartbeats WHERE last_seen<?", (timestamp(instant - 86400),)
            )
        for path in clean:
            remove_tree(path)
        for job_id in artifacts:
            remove_tree(self.registry.store.directory(job_id))

    def record_step(self, row: dict[str, Any], payload: dict[str, Any]) -> None:
        step = StepRecord.model_validate(payload)
        with self.registry.db.connect(write=True) as conn:
            updated = conn.execute(
                "UPDATE jobs SET phase=? WHERE id=? AND worker_id=? AND attempts=? "
                "AND status='running'",
                (step.id, row["id"], self.worker_id, row["attempts"]),
            ).rowcount
            if updated:
                event(conn, row["id"], "step", step.model_dump(mode="json"))
                done = sum(sid == step.id for sid, _ in STEP_TITLES)
                index = [sid for sid, _ in STEP_TITLES].index(step.id)
                progress = index + done if step.status in {"done", "skipped"} else index
                event(
                    conn,
                    row["id"],
                    "progress",
                    {
                        "phase": step.id,
                        "done": progress,
                        "total": len(STEP_TITLES),
                        "pct": int(100 * progress / len(STEP_TITLES)),
                    },
                )

    def finish(self, row: dict[str, Any], result: dict[str, Any]) -> bool:
        with self.registry.db.connect(write=True) as conn:
            owned = conn.execute(
                "SELECT id FROM jobs WHERE id=? AND worker_id=? AND attempts=? "
                "AND status='running'",
                (row["id"], self.worker_id, row["attempts"]),
            ).fetchone()
            if owned is None:
                return False
            ok = bool(result.get("ok"))
            if ok:
                output = self.scratch_for(row) / "output"
                try:
                    for name in ARTIFACT_NAMES:
                        self.registry.store.put(row["id"], name, (output / name).read_bytes())
                except (OSError, Reject):
                    ok = False
                    result = {"error_code": "INTERNAL", "detail": "Could not publish artifacts."}
            code = result.get("error_code", "INTERNAL") if not ok else None
            status = (
                "succeeded"
                if ok
                else ("timeout" if code in {"ANALYSIS_TIMEOUT", "CLONE_TIMEOUT"} else "failed")
            )
            conn.execute(
                "UPDATE jobs SET status=?,finished_at=?,error_code=?,agility_score=?,truncated=? "
                "WHERE id=?",
                (
                    status,
                    timestamp(),
                    code,
                    result.get("agility_score") if ok else None,
                    int(bool(result.get("truncated"))),
                    row["id"],
                ),
            )
            if ok:
                provenance = Provenance(
                    repo=f"{row['repo_owner']}/{row['repo_name']}",
                    commit_sha=row["commit_sha"],
                    analyzer_version=row["analyzer_version"],
                    crypto_ruleset_version=CRYPTO_RULESET_VERSION,
                )
                conn.execute(
                    "INSERT INTO analysis_cache(provenance,job_id,created_at) VALUES(?,?,?) "
                    "ON CONFLICT(provenance) DO UPDATE SET job_id=excluded.job_id,"
                    "created_at=excluded.created_at",
                    (provenance.cache_key(), row["id"], timestamp()),
                )
                event(
                    conn,
                    row["id"],
                    "done",
                    {
                        "status": status,
                        "agility_score": result["agility_score"],
                        "report_url": f"/api/v1/analyses/{row['id']}/report",
                    },
                )
            else:
                event(
                    conn,
                    row["id"],
                    "error",
                    {
                        "status": status,
                        "error_code": code,
                        "detail": result.get("detail", "The analysis failed."),
                    },
                )
        return True

    def launch(self, row: dict[str, Any]) -> None:
        scratch = self.scratch_for(row)
        scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
        messages = self.context.Queue(maxsize=64)
        proc = self.context.Process(
            target=analyze_child, args=(row, str(scratch), self.cfg, messages)
        )
        try:
            proc.start()
        except Exception:
            messages.close()
            self.finish(
                row, {"ok": False, "error_code": "INTERNAL", "detail": "Could not launch analyzer."}
            )
            remove_tree(scratch)
            return
        self.running[row["id"]] = Running(row, proc, messages, time.monotonic(), scratch)

    @staticmethod
    def kill(run: Running) -> None:
        if run.process.pid and os.name == "posix":
            try:
                os.killpg(run.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                if run.process.is_alive():
                    run.process.kill()
        elif run.process.is_alive():
            run.process.kill()
        run.process.join(timeout=2)

    def tick(self) -> None:
        for job_id in self.heartbeat():
            run = self.running.pop(job_id)
            self.kill(run)
            run.messages.close()
            remove_tree(run.scratch)
        self.sweep()
        for job_id, run in list(self.running.items()):
            result: dict[str, Any] | None = None
            while True:
                try:
                    kind, payload = run.messages.get_nowait()
                except (queue.Empty, EOFError, OSError):
                    break
                if kind == "step":
                    self.record_step(run.row, payload)
                elif kind == "result":
                    result = payload
            if (
                result is None
                and time.monotonic() - run.started > self.cfg.analysis.max_job_seconds
            ):
                result = {
                    "ok": False,
                    "error_code": "ANALYSIS_TIMEOUT",
                    "detail": "Analysis exceeded the wall-clock limit.",
                }
            if result is None and not run.process.is_alive():
                result = {
                    "ok": False,
                    "error_code": "INTERNAL",
                    "detail": "Analyzer process exited unexpectedly.",
                }
            if result is not None:
                self.kill(run)
                self.finish(run.row, result)
                run.messages.close()
                remove_tree(run.scratch)
                del self.running[job_id]
        while len(self.running) < self.cfg.worker.concurrency:
            row = self.claim()
            if row is None:
                break
            self.launch(row)

    def close(self) -> None:
        for run in self.running.values():
            self.kill(run)
            remove_tree(run.scratch)
            run.messages.close()
        self.running.clear()
        # Leave leases to expire and requeue, just as on an abrupt shutdown.

    def run(self) -> None:
        try:
            while True:
                self.tick()
                time.sleep(self.cfg.worker.poll_interval_s)
        finally:
            self.close()


def run_worker(worker_id: str, settings: Settings | None = None) -> None:
    cfg = settings or get_settings()
    registry = JobRegistry(cfg.artifact_root, cfg.db, cfg)
    Worker(registry, worker_id, cfg.scratch_root).run()
