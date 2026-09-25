"""The staged view's server side: streamed findings, disagreement, and the K1 gate."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from quanta.config import Settings, VerifySettings, get_settings
from quanta.core.analyze import analyze_path, write_artifacts
from quanta.core.fixes import review
from quanta.core.ingest import RepoMetadata
from quanta.core.models import Provenance
from quanta.errors import Reject
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version
from quanta.web.app import create_app
from quanta.web.db import timestamp
from quanta.web.jobs import JobRegistry
from quanta.web.product import pull_request_gate
from quanta.web.worker import MAX_STREAMED_EVENTS, Running, Worker

FIXTURE = Path(__file__).parents[1] / "fixtures/repos/hardcoded_crypto"


def metadata() -> RepoMetadata:
    return RepoMetadata(
        owner="owner", name="repo", default_branch="main", size_kb=1, commit_sha="a" * 40
    )


@pytest.fixture
def registry(tmp_path: Path) -> JobRegistry:
    # Verification is hidden from the web product by default; these tests turn it on.
    settings = Settings(verify=VerifySettings(web=True))
    return JobRegistry(tmp_path / "artifacts", settings=settings)


def finished_job(registry: JobRegistry, tmp_path: Path) -> tuple[str, dict]:
    job = registry.enqueue(metadata())
    worker = Worker(registry, "w1", tmp_path / "scratch")
    row = worker.claim()
    assert row
    outcome = analyze_path(
        FIXTURE,
        Provenance(
            repo="owner/repo",
            commit_sha="a" * 40,
            analyzer_version=analyzer_version(),
            crypto_ruleset_version=CRYPTO_RULESET_VERSION,
        ),
    )
    write_artifacts(outcome, worker.scratch_for(row) / "output")
    assert worker.finish(row, {"ok": True, "agility_score": outcome.score.agility_score})
    return job.id, json.loads(outcome.fixes.model_dump_json())


def set_capability(registry: JobRegistry, value: str, age: float = 0.0) -> None:
    with registry.db.connect(write=True) as conn:
        conn.execute(
            "INSERT INTO capabilities(name,value,updated_at) VALUES('verify',?,?) "
            "ON CONFLICT(name) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
            (value, timestamp(time.time() - age)),
        )


def test_worker_relays_findings_while_running_and_bounds_the_stream(
    registry: JobRegistry, tmp_path: Path
) -> None:
    job = registry.enqueue(metadata())
    worker = Worker(registry, "w1", tmp_path / "scratch")
    row = worker.claim()
    assert row
    run = Running(row, None, None, time.monotonic(), tmp_path)  # type: ignore[arg-type]
    item = {"id": "crypto_call-0123456789abcdef", "file": "a.py", "line": 3}
    worker.record_stream(run, "findings", {"file": "a.py", "items": [item]})
    events = [e for e in registry.get(job.id).events if e.event == "findings"]
    assert events and events[0].data["items"][0]["id"] == item["id"]
    with TestClient(create_app(registry.artifact_root, registry.db.path)) as client:
        streamed = client.get(f"/api/v1/analyses/{job.id}/findings").json()
        assert [f["id"] for f in streamed["findings"]] == [item["id"]]
    for _ in range(MAX_STREAMED_EVENTS + 10):
        worker.record_stream(run, "parse_progress", {"done": 1, "total": 2})
    kinds = [e.event for e in registry.get(job.id).events]
    assert kinds.count("stream_truncated") == 1
    assert kinds.count("parse_progress") + kinds.count("findings") == MAX_STREAMED_EVENTS


def test_feedback_round_trip_only_on_real_findings(registry: JobRegistry, tmp_path: Path) -> None:
    job_id, _ = finished_job(registry, tmp_path)
    with TestClient(create_app(registry.artifact_root, registry.db.path)) as client:
        listed = client.get(f"/api/v1/analyses/{job_id}/findings").json()
        assert listed["findings"] and listed["feedback"] == {}
        fid = listed["findings"][0]["id"]
        url = f"/api/v1/analyses/{job_id}/findings/{fid}/feedback"
        put = client.put(url, json={"verdict": "disagree", "reason": "test helper only"})
        assert put.status_code == 200
        again = client.get(f"/api/v1/analyses/{job_id}/findings").json()
        assert again["feedback"][fid]["verdict"] == "disagree"
        export = client.get(f"/api/v1/analyses/{job_id}/feedback").json()
        assert export["disagree"] == 1 and export["items"][0]["file"]
        # Feedback never edits the canonical score.
        before = client.get(f"/api/v1/analyses/{job_id}/score").content
        assert client.delete(url).status_code == 200
        assert client.get(f"/api/v1/analyses/{job_id}/findings").json()["feedback"] == {}
        assert client.get(f"/api/v1/analyses/{job_id}/score").content == before
        for bad in ("crypto_call-ffffffffffffffff", "../etc", "x" * 80):
            response = client.put(
                f"/api/v1/analyses/{job_id}/findings/{bad}/feedback", json={"verdict": "agree"}
            )
            assert response.status_code in {404, 405, 422}
        assert client.put(url, json={"verdict": "maybe"}).status_code == 422
        assert client.put(url, json={"verdict": "agree", "reason": "x" * 501}).status_code == 422


def test_pull_request_gate_follows_k1(registry: JobRegistry, tmp_path: Path) -> None:
    job_id, _ = finished_job(registry, tmp_path)
    digest = "d" * 64
    # No local sandbox: the gate stays open and the PR says tests were not run.
    assert pull_request_gate(registry, job_id, digest, None) is None
    set_capability(registry, "1")
    with pytest.raises(Reject) as missing:
        pull_request_gate(registry, job_id, digest, None)
    assert missing.value.code == "VERIFICATION_REQUIRED"

    def record(verdict: str) -> None:
        with registry.db.connect(write=True) as conn:
            conn.execute("DELETE FROM verifications")
            conn.execute(
                "INSERT INTO verifications(id,job_id,user_id,digest,selected,status,verdict,"
                "result,created_at) VALUES('v1',?,'local',?,'[]','done',?,?,?)",
                (job_id, digest, verdict, json.dumps({"reasons": ["r"]}), timestamp()),
            )

    record("regressed")
    with pytest.raises(Reject) as failed:
        pull_request_gate(registry, job_id, digest, "regressed")
    assert failed.value.code == "VERIFICATION_FAILED"
    record("passed_unexercised")
    with pytest.raises(Reject) as unacknowledged:
        pull_request_gate(registry, job_id, digest, None)
    assert unacknowledged.value.code == "ACKNOWLEDGEMENT_REQUIRED"
    assert pull_request_gate(registry, job_id, digest, "passed_unexercised")["verdict"] == (
        "passed_unexercised"
    )
    record("verified")
    assert pull_request_gate(registry, job_id, digest, None)["verdict"] == "verified"
    # A stale capability (no live worker) is not "available".
    set_capability(registry, "1", age=10_000)
    assert pull_request_gate(registry, job_id, digest, None)["verdict"] == "verified"


def test_verification_request_needs_a_live_sandbox_and_a_current_digest(
    registry: JobRegistry, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QUANTA_VERIFY__WEB", "true")
    get_settings.cache_clear()
    job_id, plan = finished_job(registry, tmp_path)
    ids = [c["id"] for f in plan["files"] for c in f["changes"]]
    assert ids, "the fixture must produce at least one P0 proposal"
    from quanta.core.fixes import FixPlan

    digest = review(FixPlan.model_validate(plan), ids[:1])["digest"]
    with TestClient(create_app(registry.artifact_root, registry.db.path)) as client:
        url = f"/api/v1/analyses/{job_id}/verify"
        body = {"selected": ids[:1], "digest": digest}
        assert client.post(url, json=body).json()["error_code"] == "SANDBOX_UNAVAILABLE"
        set_capability(registry, "1")
        stale = client.post(url, json={"selected": ids[:1], "digest": "0" * 64})
        assert stale.json()["error_code"] == "REVIEW_STALE"
        queued = client.post(url, json=body)
        assert queued.status_code == 202 and queued.json()["status"] == "queued"
        # The same selection is not queued twice.
        assert client.post(url, json=body).json()["id"] == queued.json()["id"]
        status = client.get(f"/api/v1/analyses/{job_id}/verification", params={"digest": digest})
        assert status.json()["verification"]["status"] == "queued"
        pr = client.post(
            f"/api/v1/analyses/{job_id}/pull-request", json={"selected": ids[:1], "digest": digest}
        )
        # Local mode has no GitHub identity; the gate order is auth first.
        assert pr.json()["error_code"] == "AUTH_REQUIRED"


def test_replay_streams_findings_inside_the_parse_step(tmp_path: Path) -> None:
    from quanta.web import examples

    example = examples.find_example("pyjwt")
    if example is None:
        pytest.skip("demo corpus is not built")
    registry = JobRegistry(tmp_path / "artifacts", settings=Settings())
    job = examples.start_replay(example, registry)
    kinds = [(e.event, e.data.get("id"), e.data.get("status")) for e in job.events]
    start = kinds.index(("step", "parse", "running"))
    end = kinds.index(("step", "parse", "done"))
    between = {k for k, _, _ in kinds[start + 1 : end]}
    assert between == {"findings"}
    streamed = sum(len(e.data["items"]) for e in job.events if e.event == "findings")
    assert streamed == example.findings
    # The summary arrives last.
    assert kinds[-1][0] == "done"


def test_sample_plays_through_the_staged_view_and_is_scored(registry: JobRegistry) -> None:
    with TestClient(create_app(registry.artifact_root, registry.db.path)) as client:
        started = client.post("/api/v1/sample/replay")
        assert started.status_code == 201 and started.json()["cached"] is True
        job_id = started.json()["job_id"]
        score = client.get(f"/api/v1/analyses/{job_id}/score").json()
        # The earlier two-module sample was refused by G6; the sample must show a score.
        assert score["status"] == "scored"
        findings = client.get(f"/api/v1/analyses/{job_id}/findings").json()["findings"]
        assert {f["category"] for f in findings} >= {"hash", "signature"}
        plan = client.get(f"/api/v1/analyses/{job_id}/fixes").json()
        ids = [c["id"] for f in plan["files"] for c in f["changes"]]
        reviewed = client.post(f"/api/v1/analyses/{job_id}/review", json={"selected": ids})
        assert reviewed.status_code == 200 and reviewed.json()["files"][0]["diff"]
        # A cached run can be reviewed but never verified or published.
        verify = client.post(
            f"/api/v1/analyses/{job_id}/verify",
            json={"selected": ids, "digest": reviewed.json()["digest"]},
        )
        assert verify.json()["error_code"] == "FIX_UNAVAILABLE"


def test_score_step_evidence_lists_each_deduction_once() -> None:
    outcome = analyze_path(
        FIXTURE,
        Provenance(
            repo="owner/repo",
            commit_sha="a" * 40,
            analyzer_version=analyzer_version(),
            crypto_ruleset_version=CRYPTO_RULESET_VERSION,
        ),
    )
    score_step = next(s for s in outcome.meta.steps if s.id == "score")
    labels = [e.label for e in score_step.evidence]
    assert len(labels) == len(set(labels)), labels


def test_web_product_hides_verification_by_default(tmp_path: Path) -> None:
    """Round four: the web product offers find, propose and readiness. Verification stays
    in the CLI and the API, and the web offers it only when QUANTA_VERIFY__WEB is set."""
    from quanta.web.review import verification_available

    registry = JobRegistry(tmp_path / "artifacts", settings=Settings())
    set_capability(registry, "1")
    assert Settings().verify.web is False
    assert verification_available(registry) is False
    job_id, _ = finished_job(registry, tmp_path)
    # With verification hidden, a pull request is never blocked waiting for one.
    assert pull_request_gate(registry, job_id, "0" * 64, None) is None


@pytest.fixture(autouse=True)
def _fresh_settings():
    yield
    get_settings.cache_clear()


def test_a_signed_out_visitor_opens_the_sample_but_not_a_live_scan(
    registry: JobRegistry, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With sign-in required (the hosted product), the recorded sample stays open."""
    live_id, _ = finished_job(registry, tmp_path)
    monkeypatch.setenv("QUANTA_AUTH__REQUIRED", "true")
    get_settings.cache_clear()
    with TestClient(create_app(registry.artifact_root, registry.db.path)) as client:
        started = client.post("/api/v1/sample/replay")
        assert started.status_code == 201
        job_id = started.json()["job_id"]
        for path in ("", "/findings", "/fixes", "/readiness", "/report", "/report.pdf"):
            assert client.get(f"/api/v1/analyses/{job_id}{path}").status_code == 200, path
        plan = client.get(f"/api/v1/analyses/{job_id}/fixes").json()
        ids = [c["id"] for f in plan["files"] for c in f["changes"]]
        assert (
            client.post(f"/api/v1/analyses/{job_id}/review", json={"selected": ids}).status_code
            == 200
        )
        live = client.get(f"/api/v1/analyses/{live_id}")
        assert live.status_code == 401 and live.json()["error_code"] == "AUTH_REQUIRED"


def test_signed_in_account_lists_its_public_repositories(
    registry: JobRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dashboard: name, avatar (GitHub's host only) and public, unarchived repositories."""
    import httpx
    from cryptography.fernet import Fernet

    from quanta.web.auth import Identity

    monkeypatch.setenv("QUANTA_AUTH__GITHUB_CLIENT_ID", "id")
    monkeypatch.setenv("QUANTA_AUTH__GITHUB_CLIENT_SECRET", "secret")
    monkeypatch.setenv("QUANTA_AUTH__ENCRYPTION_KEY", Fernet.generate_key().decode())
    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer gho_test"
        if request.url.path == "/user":
            return httpx.Response(
                200,
                json={
                    "name": "Abdullatif Example",
                    "avatar_url": "https://avatars.githubusercontent.com/u/1?v=4",
                },
            )
        assert request.url.params["visibility"] == "public"
        return httpx.Response(
            200,
            json=[
                {
                    "full_name": "someone/tool",
                    "language": "Python",
                    "pushed_at": "2026-09-01T00:00:00Z",
                },
                {"full_name": "someone/old", "archived": True},
            ],
        )

    def client_for(token: str) -> httpx.Client:
        return httpx.Client(
            base_url="https://api.github.com",
            transport=httpx.MockTransport(handler),
            headers={"Authorization": f"Bearer {token}"},
        )

    monkeypatch.setattr("quanta.web.product.github_client", client_for)
    app = create_app(registry.artifact_root, registry.db.path)
    with TestClient(app) as client:
        assert client.get("/api/v1/me").json()["error_code"] == "AUTH_REQUIRED"
        raw = app.state.auth.create_session(Identity("1", "someone", "gho_test", "c"))
        client.cookies.set(app.state.auth.cookie, raw)
        me = client.get("/api/v1/me").json()
        assert me["name"] == "Abdullatif Example" and me["login"] == "someone"
        assert me["avatar_url"].startswith("https://avatars.githubusercontent.com/")
        assert [r["full_name"] for r in me["repos"]] == ["someone/tool"]


def test_sample_replays_share_one_stored_job(registry: JobRegistry) -> None:
    """Every visitor streams the same stored replay; the database does not grow per click."""
    with TestClient(create_app(registry.artifact_root, registry.db.path)) as client:
        first = client.post("/api/v1/sample/replay").json()["job_id"]
        second = client.post("/api/v1/sample/replay").json()["job_id"]
        assert first == second
        events = client.get(f"/api/v1/analyses/{second}/events")
        assert events.status_code == 200 and "event: done" in events.text


def test_sample_replay_works_with_database_stored_artifacts(tmp_path: Path) -> None:
    """Hosted artifacts live in the database and reference their job: the row comes first."""
    from quanta.web import sample
    from quanta.web.store import DatabaseArtifactStore

    registry = JobRegistry(tmp_path / "artifacts")
    registry.store = DatabaseArtifactStore(tmp_path / "artifacts", registry.db)
    job = sample.start_replay(registry)
    assert registry.store.complete(job.id)
    assert b'"findings"' in registry.store.open(job.id, "findings.json")
    assert sample.start_replay(registry).id == job.id
