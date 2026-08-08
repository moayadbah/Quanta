"""Web tier contract (§5.2.2, §5.2.4).

Everything here runs against the cached corpus or against rejected input, so the suite
needs no network. The live analysis path is a child process and is exercised manually;
what these tests pin down is the HTTP contract, which is what any client depends on.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from quanta.errors import ERROR_CODES
from quanta.version import __version__
from quanta.web.app import create_app


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(tmp_path / "artifacts")) as test_client:
        yield test_client


@pytest.fixture
def cached_job(client: TestClient) -> str:
    """Replay a cached example and return its job id."""
    examples = client.get("/api/v1/examples").json()["examples"]
    if not examples:
        pytest.skip("demo corpus is not built")
    response = client.post(f"/api/v1/examples/{examples[0]['slug']}/replay")
    assert response.status_code == 201
    job_id: str = response.json()["job_id"]
    return job_id


# ---------------------------------------------------------------------------------------
# The six §5.2.2 endpoints
# ---------------------------------------------------------------------------------------


def test_healthz(client: TestClient) -> None:
    body = client.get("/api/v1/healthz").json()
    assert body["status"] == "ok"
    assert body["version"] == __version__
    assert "queue_depth" in body


def test_submit_returns_201_with_follow_urls(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST returns the ids a client needs and must not block on the analysis.

    ``submit`` is stubbed so no child process is spawned and no repository is cloned —
    this asserts the contract, not the analyzer.
    """
    from quanta.web.jobs import Job, JobRegistry

    fake = Job(id="11111111-1111-4111-8111-111111111111", repo_url="https://github.com/o/r")
    fake.status = "running"
    submitted: list[str] = []

    def _stub_submit(self: JobRegistry, repo_url: str) -> Job:
        submitted.append(repo_url)
        self.adopt_cached(fake)
        return fake

    monkeypatch.setattr(JobRegistry, "submit", _stub_submit)

    response = client.post(
        "/api/v1/analyses", json={"repo_url": "https://github.com/pallets/click"}
    )
    assert response.status_code == 201

    body = response.json()
    assert submitted == ["https://github.com/pallets/click"]
    assert body["job_id"] == fake.id
    assert body["status_url"] == f"/api/v1/analyses/{fake.id}"
    assert body["events_url"] == f"/api/v1/analyses/{fake.id}/events"


def test_status_endpoint_shape(client: TestClient, cached_job: str) -> None:
    body = client.get(f"/api/v1/analyses/{cached_job}").json()
    assert body["job_id"] == cached_job
    assert body["status"] == "succeeded"
    assert body["progress"] == 100
    assert body["cached"] is True
    assert body["report_url"].endswith("/report")


def test_score_endpoint_returns_the_artifact(client: TestClient, cached_job: str) -> None:
    body = client.get(f"/api/v1/analyses/{cached_job}/score").json()
    assert body["schema_version"] == "1.0"
    assert 0.0 <= body["agility_score"] <= 100.0
    assert set(body["factors"]) == {
        "call_sites",
        "isolation_layer",
        "selection_source",
        "propagation_depth",
    }


def test_report_endpoint_returns_html(client: TestClient, cached_job: str) -> None:
    response = client.get(f"/api/v1/analyses/{cached_job}/report")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<svg" in response.text


def test_cdg_endpoint_round_trips(client: TestClient, cached_job: str) -> None:
    from quanta.core.graph import from_node_link

    payload = client.get(f"/api/v1/analyses/{cached_job}/cdg").json()
    graph = from_node_link(payload)
    assert graph.number_of_nodes() > 0


def test_events_stream_is_sse(client: TestClient, cached_job: str) -> None:
    with client.stream("GET", f"/api/v1/analyses/{cached_job}/events") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())

    assert "event: plan" in body
    assert "event: step" in body
    assert "event: done" in body
    assert "id: 1" in body


def _event_ids(stream_body: str) -> list[int]:
    """Parse SSE ``id:`` lines. Substring matching would confuse ``id: 1`` with ``id: 10``."""
    return [
        int(line.removeprefix("id:").strip())
        for line in stream_body.splitlines()
        if line.startswith("id:")
    ]


def test_sse_last_event_id_resumes_exactly(client: TestClient, cached_job: str) -> None:
    """§5.2.3 / DoD-W3: reconnection resumes exactly, not approximately."""
    with client.stream("GET", f"/api/v1/analyses/{cached_job}/events") as response:
        full_ids = _event_ids("".join(response.iter_text()))

    assert full_ids == list(range(1, len(full_ids) + 1)), "ids must be a dense sequence"

    with client.stream(
        "GET", f"/api/v1/analyses/{cached_job}/events", headers={"Last-Event-ID": "3"}
    ) as response:
        resumed_ids = _event_ids("".join(response.iter_text()))

    assert resumed_ids == full_ids[3:], "resume must deliver exactly the untransmitted tail"


def test_sse_tolerates_a_malformed_last_event_id(client: TestClient, cached_job: str) -> None:
    with client.stream(
        "GET", f"/api/v1/analyses/{cached_job}/events", headers={"Last-Event-ID": "garbage"}
    ) as response:
        ids = _event_ids("".join(response.iter_text()))
    assert ids and ids[0] == 1, "an unparseable cursor restarts from the beginning"


# ---------------------------------------------------------------------------------------
# Trace (the demo's substance)
# ---------------------------------------------------------------------------------------


def test_trace_endpoint_returns_every_step_with_evidence(
    client: TestClient, cached_job: str
) -> None:
    body = client.get(f"/api/v1/analyses/{cached_job}/trace").json()
    assert body["cached"] is True
    assert len(body["steps"]) == 9

    ids = [s["id"] for s in body["steps"]]
    assert ids == [
        "validate",
        "resolve",
        "clone",
        "walk",
        "parse",
        "graph",
        "score",
        "render",
        "cleanup",
    ]
    assert all(s["status"] == "done" for s in body["steps"])
    assert all(s["evidence"] for s in body["steps"])


def test_validate_step_records_that_no_network_call_preceded_it(
    client: TestClient, cached_job: str
) -> None:
    """The SSRF ordering claim is the demo's best talking point; it must be in the data."""
    steps = client.get(f"/api/v1/analyses/{cached_job}/trace").json()["steps"]
    validate = next(s for s in steps if s["id"] == "validate")
    labels = {e["label"]: e for e in validate["evidence"]}
    assert labels["Network calls so far"]["value"].startswith("0")
    assert labels["Host allowlist"]["ok"] is True


# ---------------------------------------------------------------------------------------
# Error model (§5.2.4)
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "code", "status"),
    [
        ("https://127.0.0.1/o/r", "HOST_NOT_ALLOWED", 400),
        ("https://169.254.169.254/o/r", "HOST_NOT_ALLOWED", 400),
        ("http://github.com/o/r", "HOST_NOT_ALLOWED", 400),
        ("https://evil.com/o/r", "HOST_NOT_ALLOWED", 400),
        ("https://user:pw@github.com/o/r", "URL_MALFORMED", 400),
        ("https://github.com/o/r/extra", "URL_MALFORMED", 400),
        ("https://github.com:8080/o/r", "URL_MALFORMED", 400),
    ],
)
def test_hostile_urls_are_rejected_with_a_stable_code(
    client: TestClient, url: str, code: str, status: int
) -> None:
    response = client.post("/api/v1/analyses", json={"repo_url": url})
    assert response.status_code == status
    assert response.headers["content-type"].startswith("application/problem+json")

    body = response.json()
    assert body["error_code"] == code
    assert body["error_code"] in ERROR_CODES
    assert body["status"] == status
    assert "correlation_id" in body


def test_no_traceback_ever_reaches_a_client(client: TestClient) -> None:
    response = client.post("/api/v1/analyses", json={"repo_url": "https://evil.com/o/r"})
    text = json.dumps(response.json())
    assert "Traceback" not in text
    assert 'File "' not in text
    assert "quanta/core" not in text


def test_malformed_body_is_422_before_application_code_runs(client: TestClient) -> None:
    assert client.post("/api/v1/analyses", json={}).status_code == 422
    assert client.post("/api/v1/analyses", json={"repo_url": 12}).status_code == 422


def test_rate_limit_is_enforced_per_ip(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """§8.1: rate_limit_per_ip_hour = 10. Enforced against valid submissions."""
    from quanta.web.jobs import Job, JobRegistry

    def _stub_submit(self: JobRegistry, repo_url: str) -> Job:
        job = Job(id=f"00000000-0000-4000-8000-{len(self._jobs):012d}", repo_url=repo_url)
        job.status = "running"
        self.adopt_cached(job)
        return job

    monkeypatch.setattr(JobRegistry, "submit", _stub_submit)

    codes = [
        client.post("/api/v1/analyses", json={"repo_url": "https://github.com/o/r"}).status_code
        for _ in range(12)
    ]
    assert codes[:10] == [201] * 10
    assert codes[10] == 429

    body = client.post("/api/v1/analyses", json={"repo_url": "https://github.com/o/r"}).json()
    assert body["error_code"] == "RATE_LIMITED"


def test_rate_limit_state_is_per_app_not_global(tmp_path: Path) -> None:
    """A module-global limiter would couple every app in the process — and every test."""
    from quanta.web.app import create_app

    for i in range(2):
        with TestClient(create_app(tmp_path / f"a{i}")) as fresh:
            response = fresh.post("/api/v1/analyses", json={"repo_url": "https://evil.com/o/r"})
            assert response.json()["error_code"] == "HOST_NOT_ALLOWED"


def test_unknown_job_is_404_problem_json(client: TestClient) -> None:
    response = client.get("/api/v1/analyses/00000000-0000-4000-8000-000000000000")
    assert response.status_code == 404
    assert response.json()["error_code"] == "REPO_NOT_FOUND"


def test_artifacts_of_an_unfinished_job_are_409(client: TestClient) -> None:
    from quanta.web.jobs import Job

    registry = client.app.state.registry  # type: ignore[attr-defined]
    job = Job(id="22222222-2222-4222-8222-222222222222", repo_url="https://github.com/o/r")
    job.status = "running"
    registry.adopt_cached(job)

    response = client.get(f"/api/v1/analyses/{job.id}/score")
    assert response.status_code == 409
    assert response.json()["error_code"] == "NOT_FINISHED"


# ---------------------------------------------------------------------------------------
# Examples (ADR-022)
# ---------------------------------------------------------------------------------------


def test_examples_are_all_flagged_cached(client: TestClient) -> None:
    for example in client.get("/api/v1/examples").json()["examples"]:
        assert example["cached"] is True
        assert 0.0 <= example["agility_score"] <= 100.0


def test_unknown_example_is_rejected(client: TestClient) -> None:
    assert client.post("/api/v1/examples/nope/replay").status_code == 404


def test_about_states_the_non_claims(client: TestClient) -> None:
    """§1.4 is a control against overclaiming; the UI reads it from here."""
    body = client.get("/api/v1/about").json()
    joined = " ".join(body["does_not_claim"]).lower()
    assert "not a migration-cost estimate" in joined
    assert "not a cryptographic security review" in joined
    assert "never run" in joined or "not a code execution" in joined
