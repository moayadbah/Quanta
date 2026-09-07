from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from quanta.core.analyze import write_artifacts
from quanta.core.ingest import RepoMetadata
from quanta.web.cloud import execute, sweep
from quanta.web.db import timestamp
from quanta.web.jobs import JobRegistry
from quanta.web.product import sample_outcome
from quanta.web.store import ARTIFACT_NAMES, DatabaseArtifactStore


class RemoteFile:
    def __init__(self, data: bytes) -> None:
        self.data = data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def read(self, size: int) -> bytes:
        return self.data[:size]


class Box:
    cwd = "/vercel/sandbox"

    def __init__(self, artifacts: dict[str, bytes]) -> None:
        self.artifacts = artifacts
        self.fs = self
        self.destroyed = False
        self.policy = "github-only"
        self.stages: list[str] = []
        self.input = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.destroyed = True

    async def write_text(self, path, text):
        self.input = json.loads(text)

    def open(self, path, mode):
        return RemoteFile(self.artifacts[path.split("/")[-1]])

    async def update_network_policy(self, policy):
        self.policy = policy.mode

    async def run_process(self, command, args, **kwargs):
        phase = args[-1]
        self.stages.append(phase)
        assert self.policy == ("deny-all" if phase == "analyze" else "github-only")
        assert command == ".venv/bin/python" and args[0] == "-I"
        return SimpleNamespace(returncode=0)


def test_cloud_scan_is_isolated_persistent_bounded_and_deduplicated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = JobRegistry(tmp_path / "artifacts")
    registry.settings.cloud.enabled = True
    registry.settings.cloud.sandbox_snapshot = "snap-test"
    registry.store = DatabaseArtifactStore(tmp_path / "artifacts", registry.db)
    sample = sample_outcome()
    metadata = RepoMetadata(
        owner="sample", name="vault", commit_sha="0" * 40, default_branch="main", size_kb=1
    )
    job = registry.enqueue(metadata, "1")
    write_artifacts(sample, tmp_path / "output")
    box = Box({name: (tmp_path / "output" / name).read_bytes() for name in ARTIFACT_NAMES})
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        assert kwargs["resources"].vcpus == 1
        assert kwargs["execution_time_limit"] == 180
        assert set(kwargs["network_policy"].allow) == {"github.com", "api.github.com"}
        assert kwargs["destroy"] and not kwargs["persistent"]
        return box

    monkeypatch.setattr("quanta.web.cloud.sandbox.create_sandbox", create)
    asyncio.run(execute(registry, job.id))
    assert box.destroyed and box.stages == ["acquire", "analyze"]
    assert registry.get(job.id).status == "succeeded"
    assert registry.store.complete(job.id)
    assert b'"files"' in registry.store.open(job.id, "fixes.json")
    assert set(box.input["job"]) == {"repo_owner", "repo_name", "commit_sha"}
    assert not box.input["settings"]["auth"]["github_client_id"]
    asyncio.run(execute(registry, job.id))
    assert len(calls) == 1
    assert registry.enqueue(metadata, "1").id == job.id


def test_provider_failure_is_terminal_and_does_not_publish_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = JobRegistry(tmp_path / "artifacts")
    registry.settings.cloud.enabled = True
    registry.settings.cloud.sandbox_snapshot = "snap-test"
    job = registry.enqueue(
        RepoMetadata(owner="o", name="r", commit_sha="a" * 40, default_branch="main", size_kb=1),
        "1",
    )

    def fail(**kwargs):
        raise RuntimeError("provider secret internal detail")

    monkeypatch.setattr("quanta.web.cloud.sandbox.create_sandbox", fail)
    asyncio.run(execute(registry, job.id))
    result = registry.get(job.id)
    assert result.status == "failed" and result.error_code == "SANDBOX_UNAVAILABLE"
    assert "secret" not in result.error_detail
    assert not registry.store.complete(job.id)


def test_cloud_reclaims_lost_function_and_expires_artifacts(tmp_path: Path) -> None:
    registry = JobRegistry(tmp_path / "artifacts")
    job = registry.enqueue(
        RepoMetadata(owner="o", name="r", commit_sha="a" * 40, default_branch="main", size_kb=1),
        "1",
    )
    with registry.db.connect(write=True) as conn:
        conn.execute(
            "UPDATE jobs SET status='running',claimed_at=? WHERE id=?", (timestamp(0), job.id)
        )
    sweep(registry)
    assert registry.get(job.id).status == "timeout"
    store = DatabaseArtifactStore(tmp_path / "artifacts", registry.db)
    store.put(job.id, "fixes.json", b"{}")
    with registry.db.connect(write=True) as conn:
        conn.execute("UPDATE jobs SET created_at=? WHERE id=?", (timestamp(0), job.id))
    sweep(registry)
    with registry.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM artifact_blobs").fetchone()[0] == 0


def test_postgres_queue_artifacts_and_quota_transactions(tmp_path: Path) -> None:
    url = os.environ.get("QUANTA_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Postgres integration runs in CI with a disposable database")
    from quanta.config import Settings

    cfg = Settings(cloud={"database_url": url})
    first = JobRegistry(tmp_path / "one", settings=cfg)
    second = JobRegistry(tmp_path / "two", settings=cfg)
    metadata = RepoMetadata(
        owner="postgres", name="repo", commit_sha="a" * 40, default_branch="main", size_kb=1
    )
    job = first.enqueue(metadata, "postgres-test")
    assert second.enqueue(metadata, "postgres-test").id == job.id
    assert second.usage("postgres-test")["daily_used"] == 1
    store = DatabaseArtifactStore(tmp_path / "cloud", second.db)
    store.put(job.id, "fixes.json", b'{"files":[]}')
    assert store.open(job.id, "fixes.json") == b'{"files":[]}'
    with second.db.connect(write=True) as conn:
        conn.execute("DELETE FROM jobs WHERE id=?", (job.id,))
    with first.db.connect() as conn:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM artifact_blobs WHERE job_id=?", (job.id,)
            ).fetchone()[0]
            == 0
        )
