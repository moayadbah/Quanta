from __future__ import annotations

import asyncio
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest
from scripts import prepare_vercel

COMMIT = "a" * 40


class Builder:
    cwd = "/vercel"
    name = "quanta-release"

    def __init__(self, *, legacy: bool = False, revision: str = COMMIT) -> None:
        self.fs = self
        self.legacy = legacy
        self.revision = revision
        self.destroyed = False
        self.stopped = False
        self.installed = False
        self.sealed = False

    async def is_file(self, path):
        return self.legacy and path == PurePosixPath("/vercel/pyproject.toml")

    async def run_process(self, command, args, **options):
        if command == "git":
            assert options["cwd"] == ("/vercel" if self.legacy else "/vercel/Quanta")
            return SimpleNamespace(stdout=self.revision + "\n")
        if command == "uv":
            assert options["env"] == {"UV_PROJECT_ENVIRONMENT": "/vercel/.venv"}
            self.installed = True
        else:
            assert self.installed
            assert command == ".venv/bin/python" and options["cwd"] == self.cwd
        return SimpleNamespace(returncode=0)

    async def update_network_policy(self, policy):
        self.sealed = policy.mode == "deny-all"

    async def snapshot(self, *, expiration):
        assert self.sealed and expiration == 0
        return SimpleNamespace(id="snap-release", size_bytes=1024)

    async def stop(self):
        self.stopped = True

    async def destroy(self):
        self.destroyed = True


@pytest.mark.parametrize("legacy", [False, True])
def test_builder_keeps_snapshot_and_installs_at_scan_runtime_path(monkeypatch, legacy):
    box = Builder(legacy=legacy)

    async def create(**options):
        assert not options["persistent"]
        assert options["source"].revision == COMMIT
        return box

    async def get_snapshot(*, snapshot_id):
        assert snapshot_id == "snap-release" and box.stopped and not box.destroyed

    monkeypatch.setattr(prepare_vercel.sandbox, "create_sandbox", create)
    monkeypatch.setattr(prepare_vercel.sandbox, "get_snapshot", get_snapshot)
    asyncio.run(prepare_vercel.prepare(COMMIT))
    assert box.stopped and not box.destroyed


def test_builder_rejects_wrong_revision_before_installing_and_cleans_up(monkeypatch):
    box = Builder(revision="b" * 40)

    async def create(**options):
        return box

    monkeypatch.setattr(prepare_vercel.sandbox, "create_sandbox", create)
    with pytest.raises(RuntimeError, match="does not match"):
        asyncio.run(prepare_vercel.prepare(COMMIT))
    assert box.destroyed and not box.installed
