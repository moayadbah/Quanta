from __future__ import annotations

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from quanta.config import Settings, get_settings
from quanta.core.ingest import RepoMetadata
from quanta.errors import Reject
from quanta.web.app import create_app
from quanta.web.auth import Identity
from quanta.web.db import timestamp
from quanta.web.jobs import JobRegistry


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("QUANTA_AUTH__REQUIRED", "true")
    monkeypatch.setenv("QUANTA_AUTH__PUBLIC_URL", "http://testserver")
    monkeypatch.setenv("QUANTA_AUTH__GITHUB_CLIENT_ID", "test-client")
    monkeypatch.setenv("QUANTA_AUTH__GITHUB_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("QUANTA_AUTH__ENCRYPTION_KEY", Fernet.generate_key().decode())
    get_settings.cache_clear()
    with TestClient(create_app(tmp_path / "artifacts")) as test:
        yield test
    get_settings.cache_clear()


def sign_in(client: TestClient, user: str = "1") -> Identity:
    identity = Identity(user, "reader" + user, "private-github-token", "csrf-value")
    raw = client.app.state.auth.create_session(identity)
    client.cookies.set("quanta-local", raw)
    return identity


def metadata(name: str = "repo") -> RepoMetadata:
    return RepoMetadata(
        owner="owner", name=name, commit_sha="a" * 40, default_branch="main", size_kb=10
    )


def test_anonymous_visitors_cannot_scan_or_read_results(client: TestClient) -> None:
    job = client.app.state.registry.enqueue(metadata(), "1")
    assert (
        client.post(
            "/api/v1/analyses", json={"repo_url": "https://github.com/owner/repo"}
        ).status_code
        == 401
    )
    for suffix in ("", "/score", "/meta", "/report", "/events", "/trace", "/fixes"):
        assert client.get(f"/api/v1/analyses/{job.id}{suffix}").status_code == 401
    sample = client.get("/api/v1/sample")
    assert sample.status_code == 200 and sample.json()["sample"]
    assert len(sample.json()["fixes"]["files"]) > 0


def test_sessions_hide_encrypt_and_expire_tokens(client: TestClient) -> None:
    sign_in(client)
    response = client.get("/auth/session")
    assert response.json()["user"]["login"] == "reader1"
    assert "private-github-token" not in response.text
    assert response.headers["cache-control"] == "private, no-store"
    with client.app.state.registry.db.connect(write=True) as conn:
        stored = conn.execute("SELECT token FROM sessions").fetchone()[0]
        assert stored != "private-github-token"
        conn.execute("UPDATE sessions SET expires_at=?", (timestamp(time.time() - 1),))
    assert client.get("/auth/session").json()["user"] is None


def test_cross_account_access_and_csrf_are_refused(client: TestClient) -> None:
    job = client.app.state.registry.enqueue(metadata(), "2")
    sign_in(client, "1")
    assert client.get(f"/api/v1/analyses/{job.id}").status_code == 404
    assert client.get("/api/v1/workspace").json()["jobs"] == []
    for headers in (
        {},
        {"origin": "https://attacker.example", "x-csrf-token": "csrf-value"},
        {"origin": "http://testserver", "x-csrf-token": "wrong"},
    ):
        assert client.post("/auth/logout", headers=headers).status_code == 403
    assert (
        client.post(
            "/auth/logout", headers={"origin": "http://testserver", "x-csrf-token": "csrf-value"}
        ).status_code
        == 200
    )
    assert client.get("/auth/session").json()["user"] is None


def test_oauth_state_pkce_and_callback_binding(client: TestClient) -> None:
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 303
    params = parse_qs(urlparse(response.headers["location"]).query)
    assert params["code_challenge_method"] == ["S256"]
    assert len(params["code_challenge"][0]) == 43
    state = params["state"][0]
    assert "httponly" in response.headers["set-cookie"].lower()
    assert client.get("/auth/callback?state=wrong&code=wrong").status_code == 401
    with client.app.state.registry.db.connect() as conn:
        row = conn.execute("SELECT id FROM oauth_states").fetchone()
        assert row[0] == hashlib.sha256(state.encode()).hexdigest()
    # A missing code consumes the matched state, which cannot be replayed.
    assert client.get("/auth/callback", params={"state": state}).status_code == 401
    with client.app.state.registry.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM oauth_states").fetchone()[0] == 0


def test_expired_results_are_not_readable_or_listed(client: TestClient) -> None:
    job = client.app.state.registry.enqueue(metadata(), "1")
    sign_in(client)
    with client.app.state.registry.db.connect(write=True) as conn:
        conn.execute(
            "UPDATE jobs SET created_at=? WHERE id=?", (timestamp(time.time() - 8 * 86400), job.id)
        )
    assert client.get(f"/api/v1/analyses/{job.id}").status_code == 404
    assert not client.get("/api/v1/workspace").json()["jobs"]


def test_limits_are_atomic_across_instances_and_survive_restarts(tmp_path: Path) -> None:
    cfg = Settings()
    cfg.product.scans_per_user_day = 3
    first = JobRegistry(tmp_path / "artifacts", settings=cfg)
    second = JobRegistry(tmp_path / "artifacts", settings=cfg)

    def submit(index: int) -> bool:
        try:
            (first if index % 2 else second).enqueue(metadata(f"repo{index}"), "1")
            return True
        except Reject as exc:
            assert exc.code == "QUOTA_EXCEEDED"
            return False

    with ThreadPoolExecutor(max_workers=6) as pool:
        assert sum(pool.map(submit, range(10))) == 3
    reopened = JobRegistry(tmp_path / "artifacts", settings=cfg)
    assert reopened.usage("1")["daily_used"] == 3
    assert reopened.usage("1")["monthly_used"] == 3


def test_reused_scan_does_not_spend_compute_twice(client: TestClient) -> None:
    registry = client.app.state.registry
    first = registry.enqueue(metadata(), "1")
    second = registry.enqueue(metadata(), "2")
    assert first.id == second.id
    assert registry.usage("2")["daily_used"] == 0
    sign_in(client, "2")
    assert client.get(f"/api/v1/analyses/{first.id}").status_code == 200


def test_scanner_settings_exclude_all_service_credentials(client: TestClient) -> None:
    cfg = client.app.state.registry.settings
    cfg.cloud.database_url = "postgresql://secret"
    serialized = cfg.scanner_settings().model_dump_json()
    for secret in ("test-secret", "test-client", "postgresql://secret", "private-github-token"):
        assert secret not in serialized
    assert not cfg.scanner_settings().auth.required
