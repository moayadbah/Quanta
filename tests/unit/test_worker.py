from __future__ import annotations

import multiprocessing as mp
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from quanta.config import Settings
from quanta.core.analyze import analyze_path, write_artifacts
from quanta.core.ingest import RepoMetadata
from quanta.core.models import Provenance, StepRecord
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version
from quanta.web.app import create_app
from quanta.web.db import timestamp
from quanta.web.jobs import JobRegistry
from quanta.web.worker import Running, Worker


def metadata(name: str = "repo") -> RepoMetadata:
    return RepoMetadata(
        owner="owner", name=name, default_branch="main", size_kb=1, commit_sha="a" * 40
    )


@pytest.fixture
def registry(tmp_path: Path) -> JobRegistry:
    return JobRegistry(tmp_path / "artifacts", settings=Settings())


def test_job_and_events_survive_api_restart(registry: JobRegistry) -> None:
    job = registry.enqueue(metadata())
    worker = Worker(registry, "w1", registry.artifact_root.parent / "scratch")
    claimed = worker.claim()
    assert claimed
    worker.record_step(claimed, StepRecord(id="clone", title="Clone", status="done").model_dump())
    with TestClient(create_app(registry.artifact_root, registry.db.path)) as first:
        assert first.get(f"/api/v1/analyses/{job.id}").json()["status"] == "running"
    with TestClient(create_app(registry.artifact_root, registry.db.path)) as second:
        assert second.get(f"/api/v1/analyses/{job.id}").json()["phase"] == "clone"
        assert second.get(f"/api/v1/analyses/{job.id}/trace").json()["steps"][0]["status"] == "done"


def test_claim_is_atomic_and_concurrency_is_global(registry: JobRegistry) -> None:
    for i in range(4):
        registry.enqueue(metadata(f"repo{i}"))
    workers = [
        Worker(registry, f"w{i}", registry.artifact_root.parent / "scratch") for i in range(6)
    ]
    with ThreadPoolExecutor(6) as pool:
        claimed = list(pool.map(lambda w: w.claim(), workers))
    ids = [row["id"] for row in claimed if row]
    assert len(ids) == len(set(ids)) == 2


def test_stale_lease_retries_then_stops_and_rejects_old_results(registry: JobRegistry) -> None:
    job = registry.enqueue(metadata())
    worker = Worker(registry, "w1", registry.artifact_root.parent / "scratch")
    first = worker.claim()
    assert first
    old_scratch = worker.scratch_for(first)
    old_scratch.mkdir()
    (old_scratch / "source.py").write_text("untrusted source")
    worker.sweep(time.time() + registry.settings.worker.claim_ttl_s + 1)
    assert not old_scratch.exists()
    assert registry.get(job.id).status == "queued"
    second = worker.claim()
    assert second and second["attempts"] == 2
    assert not worker.finish(first, {"ok": False})
    assert registry.get(job.id).status == "running"
    worker.sweep(time.time() + registry.settings.worker.claim_ttl_s + 1)
    assert registry.get(job.id).status == "failed"
    assert worker.claim() is None
    assert registry.get(job.id).events[-1].event == "error"


def test_success_publishes_and_reuses_provenance(registry: JobRegistry, tmp_path: Path) -> None:
    job = registry.enqueue(metadata())
    worker = Worker(registry, "w1", tmp_path / "scratch")
    row = worker.claim()
    assert row
    fixture = Path(__file__).parents[1] / "fixtures/repos/no_crypto"
    provenance = Provenance(
        repo="owner/repo",
        commit_sha="a" * 40,
        analyzer_version=analyzer_version(),
        crypto_ruleset_version=CRYPTO_RULESET_VERSION,
    )
    outcome = analyze_path(fixture, provenance)
    write_artifacts(outcome, worker.scratch_for(row) / "output")
    assert worker.finish(row, {"ok": True, "agility_score": outcome.score.agility_score})
    reopened = JobRegistry(registry.artifact_root, registry.db.path)
    reused = reopened.enqueue(metadata())
    assert reused.id == job.id and reused.reused
    assert reopened.store.complete(job.id)
    assert reopened.get(job.id).status == "succeeded"
    assert len([e for e in reopened.get(job.id).events if e.event == "done"]) == 1
    assert not worker.finish(row, {"ok": True, "agility_score": 100})


def test_missing_artifact_invalidates_cache(registry: JobRegistry) -> None:
    job = registry.enqueue(metadata())
    with registry.db.connect(write=True) as conn:
        conn.execute("UPDATE jobs SET status='succeeded' WHERE id=?", (job.id,))
    new_job = registry.enqueue(metadata())
    assert new_job.id != job.id


def _sleep() -> None:
    time.sleep(30)


def test_watchdog_kills_without_any_api_request(registry: JobRegistry, tmp_path: Path) -> None:
    job = registry.enqueue(metadata())
    worker = Worker(registry, "w1", tmp_path / "scratch")
    row = worker.claim()
    assert row
    scratch = worker.scratch_for(row)
    scratch.mkdir()
    (scratch / "source.py").write_text("hostile input")
    context = mp.get_context("spawn")
    process = context.Process(target=_sleep)
    messages = context.Queue()
    process.start()
    worker.running[job.id] = Running(row, process, messages, time.monotonic() - 1000, scratch)
    try:
        worker.tick()
        assert not process.is_alive()
        assert registry.get(job.id).status == "timeout"
        assert not scratch.exists()
    finally:
        worker.close()
        if process.is_alive():
            process.kill()
            process.join()


def test_health_heartbeat_and_retention(registry: JobRegistry, tmp_path: Path) -> None:
    assert registry.heartbeat_age() is None
    worker = Worker(registry, "w1", tmp_path / "scratch")
    worker.heartbeat()
    assert registry.heartbeat_age() < 5
    job = registry.enqueue(metadata())
    registry.store.put(job.id, "report.html", b"report")
    with registry.db.connect(write=True) as conn:
        conn.execute(
            "UPDATE jobs SET status='failed',finished_at=? WHERE id=?",
            (timestamp(time.time() - 8 * 86400), job.id),
        )
    worker.sweep()
    assert registry.get(job.id) is None
    assert not registry.store.directory(job.id).exists()
