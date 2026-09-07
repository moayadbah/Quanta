from __future__ import annotations

import base64
from pathlib import Path

import httpx
import pytest

from quanta.core.fixes import FixPlan, propose, review
from quanta.core.ingest import RepoMetadata
from quanta.errors import Reject
from quanta.web.auth import Identity
from quanta.web.jobs import JobRegistry
from quanta.web.pulls import _publish, open_pull

SOURCE = 'import hashlib\nx = hashlib.md5(b"x")\n'
SHA = "a" * 40


def fixture_plan() -> FixPlan:
    file = propose(SOURCE, "hashes.py")
    assert file
    return FixPlan(files=[file])


class GitHub:
    def __init__(self) -> None:
        self.writes: list[tuple[str, dict]] = []
        self.stale = False
        self.mode = "100755"
        self.blob = SOURCE
        self.ref = False
        self.changed_branch = False
        self.existing = False
        self.direct = True
        self.fork_ready = True
        self.fork_source = "owner/repo"

    def handle(self, request: httpx.Request) -> httpx.Response:
        import json

        path = request.url.path
        if request.method == "POST":
            data = json.loads(request.content)
            self.writes.append((path, data))
            if path.endswith("/git/trees"):
                return httpx.Response(201, json={"sha": "newtree"})
            if path.endswith("/git/commits"):
                return httpx.Response(201, json={"sha": "newcommit"})
            if path.endswith("/git/refs"):
                self.ref = True
                return httpx.Response(201, json={})
            if path.endswith("/pulls"):
                self.existing = True
                return httpx.Response(
                    201, json={"html_url": "https://github.com/owner/repo/pull/7"}
                )
            if path.endswith("/forks"):
                return httpx.Response(202, json={})
        if path == "/repos/reader/repo":
            if not self.fork_ready:
                return httpx.Response(404, json={})
            return httpx.Response(
                200,
                json={"fork": True, "owner": {"id": 1}, "source": {"full_name": self.fork_source}},
            )
        if path == "/repos/owner/repo":
            return httpx.Response(
                200,
                json={
                    "default_branch": "main",
                    "full_name": "owner/repo",
                    "permissions": {"push": self.direct},
                },
            )
        if path.endswith("/pulls"):
            return httpx.Response(
                200,
                json=[{"html_url": "https://github.com/owner/repo/pull/7"}]
                if self.existing
                else [],
            )
        if path.endswith("/commits/main"):
            return httpx.Response(200, json={"sha": "b" * 40 if self.stale else SHA})
        if path.endswith("/git/commits/" + SHA):
            return httpx.Response(200, json={"tree": {"sha": "base"}})
        if path.endswith("/git/trees/base"):
            return httpx.Response(
                200,
                json={
                    "tree": [
                        {"path": "hashes.py", "sha": "blob", "mode": self.mode, "type": "blob"}
                    ]
                },
            )
        if path.endswith("/git/blobs/blob"):
            return httpx.Response(
                200,
                json={
                    "encoding": "base64",
                    "size": len(self.blob),
                    "content": base64.b64encode(self.blob.encode()).decode(),
                },
            )
        if "/git/ref/heads/" in path:
            return (
                httpx.Response(200, json={"object": {"sha": "newcommit"}})
                if self.ref
                else httpx.Response(404, json={})
            )
        if path.endswith("/git/commits/newcommit"):
            return httpx.Response(
                200,
                json={
                    "tree": {"sha": "wrong" if self.changed_branch else "newtree"},
                    "parents": [{"sha": SHA}],
                },
            )
        raise AssertionError(f"Unexpected GitHub request {request.method} {path}")


def publish(fake: GitHub) -> str:
    plan = fixture_plan()
    result = review(plan, [plan.files[0].changes[0].id])
    with httpx.Client(
        base_url="https://api.github.com", transport=httpx.MockTransport(fake.handle)
    ) as client:
        return _publish(
            client,
            {
                "repo_owner": "owner",
                "repo_name": "repo",
                "commit_sha": SHA,
                "default_branch": "main",
            },
            Identity("1", "reader", "secret", "csrf"),
            result,
            "quanta/test",
        )


def test_exact_review_becomes_draft_pr_and_retry_reuses_it() -> None:
    fake = GitHub()
    assert publish(fake).endswith("/pull/7")
    tree = next(data for path, data in fake.writes if path.endswith("/git/trees"))
    assert tree["base_tree"] == "base"
    assert tree["tree"] == [
        {
            "path": "hashes.py",
            "mode": "100755",
            "type": "blob",
            "content": SOURCE.replace("md5", "sha256"),
        }
    ]
    pull = fake.writes[-1][1]
    assert pull["draft"] is True and pull["maintainer_can_modify"] is False
    assert "tests were not run" in pull["body"]
    writes = len(fake.writes)
    assert publish(fake).endswith("/pull/7")
    assert len(fake.writes) == writes


@pytest.mark.parametrize("kind", ["stale", "symlink", "source"])
def test_stale_source_and_symlinks_never_write(kind: str) -> None:
    fake = GitHub()
    if kind == "stale":
        fake.stale = True
    if kind == "symlink":
        fake.mode = "120000"
    if kind == "source":
        fake.blob = "changed"
    with pytest.raises(Reject):
        publish(fake)
    assert fake.writes == []


def test_an_edited_quanta_branch_is_never_overwritten() -> None:
    fake = GitHub()
    fake.ref = fake.changed_branch = True
    with pytest.raises(Reject, match="PR_CONFLICT"):
        publish(fake)
    assert not any(path.endswith(("/git/refs", "/pulls")) for path, _ in fake.writes)


def test_new_fork_returns_retryable_pending_then_opens_pr() -> None:
    fake = GitHub()
    fake.direct = fake.fork_ready = False
    with pytest.raises(Reject, match="PR_PENDING"):
        publish(fake)
    assert fake.writes[0][0] == "/repos/owner/repo/forks"
    fake.fork_ready = True
    assert publish(fake).endswith("/pull/7")
    assert fake.writes[-1][1]["head"] == "reader:quanta/test"


def test_unrelated_fork_is_never_modified() -> None:
    fake = GitHub()
    fake.direct = False
    fake.fork_source = "someone/else"
    with pytest.raises(Reject, match="PR_CONFLICT"):
        publish(fake)
    assert fake.writes == []


def test_digest_tampering_never_reaches_github(tmp_path: Path) -> None:
    registry = JobRegistry(tmp_path / "artifacts")
    plan = fixture_plan()
    with pytest.raises(Reject, match="REVIEW_STALE"):
        open_pull(
            registry,
            "unknown",
            Identity("1", "reader", "secret", "csrf"),
            plan,
            [plan.files[0].changes[0].id],
            "0" * 64,
        )


def test_persisted_success_survives_a_new_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = JobRegistry(tmp_path / "artifacts")
    job = registry.enqueue(
        RepoMetadata(owner="owner", name="repo", commit_sha=SHA, default_branch="main", size_kb=1),
        "1",
    )
    with registry.db.connect(write=True) as conn:
        conn.execute("UPDATE jobs SET status='succeeded' WHERE id=?", (job.id,))
    plan = fixture_plan()
    selected = [plan.files[0].changes[0].id]
    digest = review(plan, selected)["digest"]
    calls = []

    def mocked(*args):
        calls.append(True)
        return "https://github.com/owner/repo/pull/7"

    monkeypatch.setattr("quanta.web.pulls._publish", mocked)
    identity = Identity("1", "reader", "secret", "csrf")
    first = open_pull(registry, job.id, identity, plan, selected, digest)
    reopened = JobRegistry(tmp_path / "artifacts")
    assert open_pull(reopened, job.id, identity, plan, selected, digest) == first
    assert len(calls) == 1
