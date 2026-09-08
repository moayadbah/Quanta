"""Build one trusted scanner snapshot. Requires Vercel Hobby credentials locally.

Usage: uv run python scripts/prepare_vercel.py --commit <tested-40-character-sha>
The API token authenticates SDK calls only; it is never put inside the snapshot.
"""

from __future__ import annotations

import argparse
import asyncio
import re
from pathlib import PurePosixPath

from vercel import sandbox
from vercel.sandbox import GitSource, NetworkPolicy, SandboxResources


async def prepare(commit: str) -> None:
    box = await sandbox.create_sandbox(
        source=GitSource(url="https://github.com/moayadbah/Quanta.git", revision=commit, depth=1),
        resources=SandboxResources(vcpus=1, memory=2048),
        execution_time_limit=600,
        persistent=False,
    )
    snapshot = None
    try:
        if not box.cwd:
            raise RuntimeError("The builder has no working directory")
        root = PurePosixPath(box.cwd)
        # Current Sandbox images clone GitSource into a repository-named child.
        # Older images placed it directly in cwd. Keep the runtime venv in cwd
        # because cloud.py launches it there when restoring this snapshot.
        checkout = root if await box.fs.is_file(root / "pyproject.toml") else root / "Quanta"
        revision = await box.run_process(
            "git", ["rev-parse", "HEAD"], cwd=str(checkout), capture_output=True, check=True
        )
        if revision.stdout is None or revision.stdout.strip() != commit:
            raise RuntimeError("The scanner checkout does not match the requested commit")
        await box.run_process(
            "uv",
            ["sync", "--locked", "--no-editable", "--python", "3.12"],
            cwd=str(checkout),
            env={"UV_PROJECT_ENVIRONMENT": str(root / ".venv")},
            check=True,
            kill_after=480,
        )
        await box.run_process(
            ".venv/bin/python",
            [
                "-I",
                "-c",
                "from quanta.web.product import sample; "
                "assert sample()['fixes']['files']; print('Scanner ready')",
            ],
            cwd=box.cwd,
            check=True,
            kill_after=30,
        )
        await box.update_network_policy(NetworkPolicy.deny_all())
        snapshot = await box.snapshot(expiration=0)
    finally:
        if snapshot is None:
            await box.destroy()
        else:
            # Destroying the builder also deletes its snapshots. Stop compute
            # while retaining this release's snapshot for disposable scan VMs.
            await box.stop()
    await sandbox.get_snapshot(snapshot_id=snapshot.id)
    print("QUANTA_CLOUD__SANDBOX_SNAPSHOT=" + snapshot.id)
    print("Trusted source commit: " + commit)
    print("Snapshot bytes: " + str(snapshot.size_bytes))
    print("Retained builder sandbox: " + box.name)
    print("Destroy the previous builder only after verifying the new deployment.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.commit):
        parser.error("--commit must be the complete SHA of a tested Quanta commit")
    asyncio.run(prepare(args.commit))
