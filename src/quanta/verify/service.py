"""Verification as a product service (PROTOCOL-R3 K1).

A reviewer asks for verification of one reviewed selection (identified by its review
digest). The local worker clones the repository again at the pinned commit, applies
exactly that selection, and runs :func:`quanta.verify.pipeline.verify_changes` in the
Docker sandbox. The verdict is stored with the digest, and the pull-request path reads
it: when verification is available, no proposal becomes a pull request without one.

Docker is only ever driven from this package; the analysis and web planes run git and
nothing else (``tests/security/test_no_target_import.py``).
"""

from __future__ import annotations

import json
import multiprocessing as mp
import queue
import time
import uuid
from dataclasses import dataclass
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import Any

from quanta.config import Settings
from quanta.core.fixes import FixPlan, review
from quanta.core.ingest import clone_pinned, remove_tree
from quanta.errors import Reject

#: How long a capability probe stays valid, for the worker (writer) and the API (reader).
CAPABILITY_TTL_S = 180.0
_PROBE_EVERY_S = 60.0


def summary(verdict: dict[str, Any]) -> dict[str, Any]:
    """The stored, public part of a verdict. Raw logs stay on the worker's disk."""
    mutants = verdict.get("site_mutants") or []
    return {
        "verdict": verdict.get("verdict", "unverifiable"),
        "reasons": list(verdict.get("reasons", [])),
        "stable_pass": verdict.get("stable_pass"),
        "regressions": list(verdict.get("regressions") or [])[:50],
        "unexecuted_changed_lines": verdict.get("unexecuted_changed_lines"),
        "site_mutants": {
            "total": len(mutants),
            "killed": sum(bool(m.get("killed")) for m in mutants),
        },
        "install_rule": verdict.get("install_rule"),
    }


def verify_child(
    job: dict[str, Any],
    record: dict[str, Any],
    plan_json: str,
    scratch: str,
    cfg: Settings,
    messages: Any,
) -> None:
    """Runs in a spawned process: clone, apply the reviewed selection, verify."""
    from quanta.verify.pipeline import verify_changes

    try:
        plan = FixPlan.model_validate_json(plan_json)
        result = review(plan, json.loads(record["selected"]))
        if result["digest"] != record["digest"]:
            raise Reject("REVIEW_STALE", "the stored selection no longer matches its digest")
        root = Path(scratch)
        source = root / "repo"
        clone_pinned(job["repo_owner"], job["repo_name"], job["commit_sha"], source, cfg)
        files = [{"path": f["path"], "content": f["content"]} for f in result["files"]]
        verdict = verify_changes(source, files, root / "verify", f"{job['repo_name']}-web")
        messages.put(("result", {"ok": True, **summary(verdict.public())}))
    except Reject as exc:
        messages.put(("result", {"ok": False, "verdict": "unverifiable", "reasons": [exc.detail]}))
    except Exception:
        messages.put(
            (
                "result",
                {
                    "ok": False,
                    "verdict": "unverifiable",
                    "reasons": ["the verifier could not complete this selection"],
                },
            )
        )


@dataclass
class _Active:
    record: dict[str, Any]
    process: BaseProcess
    messages: Any
    started: float
    scratch: Path


class VerificationRunner:
    """One verification at a time, driven from the worker's tick."""

    def __init__(self, registry: Any, worker_id: str, scratch_root: Path) -> None:
        self.registry = registry
        self.cfg: Settings = registry.settings
        self.worker_id = worker_id
        self.scratch_root = scratch_root
        self.context = mp.get_context("spawn")
        self.active: _Active | None = None
        self.capable = False
        self._probed = 0.0
        self._recover()

    def _recover(self) -> None:
        """A verification this worker left running cannot resume; say so honestly."""
        from quanta.web.db import timestamp

        with self.registry.db.connect(write=True) as conn:
            conn.execute(
                "UPDATE verifications SET status='failed',verdict='unverifiable',result=?,"
                "finished_at=? WHERE status='running' AND worker_id=?",
                (
                    json.dumps({"verdict": "unverifiable", "reasons": ["the worker restarted"]}),
                    timestamp(),
                    self.worker_id,
                ),
            )

    def enabled(self) -> bool:
        return self.cfg.verify.mode == "auto" and not self.cfg.cloud.enabled

    def probe(self) -> None:
        from quanta.verify.sandbox import docker_available
        from quanta.web.db import timestamp

        now = time.monotonic()
        if self._probed and now - self._probed < _PROBE_EVERY_S:
            return
        self._probed = now
        self.capable = self.enabled() and docker_available()
        with self.registry.db.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO capabilities(name,value,updated_at) VALUES('verify',?,?) "
                "ON CONFLICT(name) DO UPDATE SET value=excluded.value,"
                "updated_at=excluded.updated_at",
                ("1" if self.capable else "0", timestamp()),
            )

    def claim(self) -> tuple[dict[str, Any], dict[str, Any]] | None:
        from quanta.web.db import timestamp

        with self.registry.db.connect(write=True) as conn:
            row = conn.execute(
                "UPDATE verifications SET status='running',worker_id=? "
                "WHERE id=(SELECT id FROM verifications WHERE status='queued' "
                "ORDER BY created_at,id LIMIT 1) RETURNING *",
                (self.worker_id,),
            ).fetchone()
            if row is None:
                return None
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (row["job_id"],)).fetchone()
            if job is None:
                conn.execute(
                    "UPDATE verifications SET status='failed',finished_at=? WHERE id=?",
                    (timestamp(), row["id"]),
                )
                return None
            return dict(row), dict(job)

    def finish(self, record: dict[str, Any], result: dict[str, Any]) -> None:
        from quanta.web.db import timestamp

        public = {k: v for k, v in result.items() if k != "ok"}
        status = "done" if result.get("ok") else "failed"
        with self.registry.db.connect(write=True) as conn:
            conn.execute(
                "UPDATE verifications SET status=?,verdict=?,result=?,finished_at=? "
                "WHERE id=? AND worker_id=?",
                (
                    status,
                    public.get("verdict", "unverifiable"),
                    json.dumps(public, sort_keys=True),
                    timestamp(),
                    record["id"],
                    self.worker_id,
                ),
            )

    def tick(self) -> None:
        if not self.enabled():
            return
        self.probe()
        if self.active is not None:
            self._poll(self.active)
            return
        if not self.capable:
            return
        claimed = self.claim()
        if claimed is None:
            return
        record, job = claimed
        try:
            plan_json = self.registry.store.open(job["id"], "fixes.json").decode("utf-8")
        except (OSError, Reject):
            self.finish(
                record, {"ok": False, "verdict": "unverifiable", "reasons": ["no stored plan"]}
            )
            return
        scratch = self.scratch_root / f"verify-{uuid.uuid4()}"
        scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
        messages = self.context.Queue(maxsize=4)
        process = self.context.Process(
            target=verify_child,
            args=(job, record, plan_json, str(scratch), self.cfg.scanner_settings(), messages),
        )
        process.start()
        self.active = _Active(record, process, messages, time.monotonic(), scratch)

    def _poll(self, active: _Active) -> None:
        result: dict[str, Any] | None = None
        try:
            kind, payload = active.messages.get_nowait()
            if kind == "result":
                result = payload
        except (queue.Empty, EOFError, OSError):
            pass
        if result is None and time.monotonic() - active.started > self.cfg.verify.max_seconds:
            result = {
                "ok": False,
                "verdict": "unverifiable",
                "reasons": ["verification exceeded its time limit"],
            }
        if result is None and not active.process.is_alive():
            result = {
                "ok": False,
                "verdict": "unverifiable",
                "reasons": ["the verifier process exited unexpectedly"],
            }
        if result is None:
            return
        if active.process.is_alive():
            active.process.kill()
        active.process.join(timeout=2)
        active.messages.close()
        self.finish(active.record, result)
        remove_tree(active.scratch)
        self.active = None

    def close(self) -> None:
        if self.active is not None:
            if self.active.process.is_alive():
                self.active.process.kill()
            remove_tree(self.active.scratch)
            self.active = None
