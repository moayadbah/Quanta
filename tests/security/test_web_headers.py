"""Web tier security headers and boundary behaviour (§7.3, A05).

The SPA and the report have deliberately *different* policies, and the difference is the
point: the SPA needs to run its own JavaScript, the report needs to run nothing at all.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from quanta.core.report import REPORT_SECURITY_HEADERS
from quanta.web.app import SPA_CSP, create_app


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(tmp_path / "artifacts")) as test_client:
        yield test_client


def _directive(csp: str, name: str) -> str:
    for part in csp.split(";"):
        part = part.strip()
        if part.startswith(f"{name} "):
            return part
    return ""


# ---------------------------------------------------------------------------------------
# SPA
# ---------------------------------------------------------------------------------------


def test_spa_csp_has_no_unsafe_inline(client: TestClient) -> None:
    """The whole reason app.js and app.css are separate files.

    An inline-script allowance would forfeit most of what CSP buys, so the SPA is written
    with no inline ``<script>`` or ``<style>`` at all.
    """
    csp = client.get("/").headers["content-security-policy"]
    assert "unsafe-inline" not in _directive(csp, "script-src")
    assert "'self'" in _directive(csp, "script-src")
    assert _directive(csp, "default-src") == "default-src 'none'"


def test_spa_sets_the_hardening_headers(client: TestClient) -> None:
    headers = client.get("/").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert "frame-src 'self'" in headers["content-security-policy"]


def test_spa_source_contains_no_inline_script_or_style() -> None:
    """Static assertion: a future inline handler would silently need 'unsafe-inline'."""
    import re

    static = Path(__file__).resolve().parents[2] / "src" / "quanta" / "web" / "static"
    raw = (static / "index.html").read_text(encoding="utf-8")
    # Strip HTML comments first: the file documents *why* it has no inline script, and
    # that prose mentions the tag by name. A comment is not executable.
    html = re.sub(r"<!--.*?-->", "", raw, flags=re.DOTALL)

    inline_scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", html, flags=re.IGNORECASE)
    assert inline_scripts == [], f"inline <script> would require 'unsafe-inline': {inline_scripts}"
    assert not re.search(r"<style[\s>]", html, flags=re.IGNORECASE)
    assert not re.search(r"\son(click|load|error|submit)\s*=", html, flags=re.IGNORECASE)


def test_spa_csp_constant_matches_what_is_served(client: TestClient) -> None:
    assert client.get("/").headers["content-security-policy"] == SPA_CSP


def test_the_spa_never_sets_an_inline_style_from_javascript() -> None:
    """``style-src 'self'`` blocks JS-set styles too, and it does so silently.

    This is not theoretical. Setting ``element.style.width`` from ``app.js`` was blocked
    by this policy with no visible failure: the analyzer's progress bar never moved, and
    the three score bars in the walkthrough all rendered at the same length — destroying
    the comparison that act exists to make. Nothing threw; the values were simply dropped.

    Continuous values therefore travel as SVG geometry attributes, and staged delays as
    ``nth-child`` rules. Neither is a style, so neither can be blocked.
    """
    import re

    source = (
        Path(__file__).resolve().parents[2] / "src" / "quanta" / "web" / "static" / "app.js"
    ).read_text(encoding="utf-8")

    offenders = re.findall(r"\.style\.(?:setProperty\(|[A-Za-z]+\s*=)", source)
    assert not offenders, (
        f"JS-set inline styles are silently dropped under style-src 'self': {offenders}"
    )


# ---------------------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------------------


@pytest.fixture
def cached_job(client: TestClient) -> str:
    examples = client.get("/api/v1/examples").json()["examples"]
    if not examples:
        pytest.skip("demo corpus is not built")
    return str(client.post(f"/api/v1/examples/{examples[0]['slug']}/replay").json()["job_id"])


def test_report_keeps_its_own_stricter_policy(client: TestClient, cached_job: str) -> None:
    """The SPA middleware must never overwrite the report's headers."""
    headers = client.get(f"/api/v1/analyses/{cached_job}/report").headers
    for name, value in REPORT_SECURITY_HEADERS.items():
        assert headers[name.lower()] == value

    csp = headers["content-security-policy"]
    assert _directive(csp, "default-src") == "default-src 'none'"
    assert "script-src" not in csp, "the report runs nothing, so nothing may be allowed"


def test_report_uses_frame_ancestors_not_x_frame_options(
    client: TestClient, cached_job: str
) -> None:
    """Verified in a browser: X-Frame-Options blanks a sandboxed iframe.

    A ``sandbox`` iframe has an opaque origin, so ``SAMEORIGIN`` can never match and the
    report renders blank — the header defeats the feature it protects. ``frame-ancestors``
    tests the embedding page's origin instead, which lets the sandbox stay at full
    strength (no allow-same-origin, no allow-scripts).
    """
    headers = client.get(f"/api/v1/analyses/{cached_job}/report").headers
    assert "frame-ancestors 'self'" in headers["content-security-policy"]
    assert "x-frame-options" not in headers


def test_report_is_embedded_with_a_restrictive_sandbox() -> None:
    static = Path(__file__).resolve().parents[2] / "src" / "quanta" / "web" / "static"
    html = (static / "guide.html").read_text(encoding="utf-8")
    assert 'id="report-frame"' in html
    assert 'sandbox=""' in html, "an empty sandbox grants nothing — no scripts, no same-origin"


# ---------------------------------------------------------------------------------------
# Ingestion controls still apply through HTTP
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/o/r",
        "https://169.254.169.254/o/r",
        "https://[::1]/o/r",
        "https://10.0.0.1/o/r",
        "file:///etc/passwd",
        "https://github.com/../../etc/passwd",
        "https://github.com/o/r\x00",
    ],
)
def test_ssrf_controls_apply_at_the_http_boundary(client: TestClient, url: str) -> None:
    """The web tier adds no new validation — it reuses core.ingest, so this is a wiring
    check that the reuse actually happened."""
    response = client.post("/api/v1/analyses", json={"repo_url": url})
    assert response.status_code in {400, 422}
    if response.status_code == 400:
        assert response.json()["error_code"] in {"HOST_NOT_ALLOWED", "URL_MALFORMED"}


def test_job_ids_are_unguessable_capabilities(client: TestClient, cached_job: str) -> None:
    """§7.3: reports are addressed by UUIDv4 — 122 bits, stated as capability access."""
    import uuid

    parsed = uuid.UUID(cached_job)
    assert parsed.version == 4


def test_artifact_paths_are_not_built_from_user_input(client: TestClient) -> None:
    """A01: traversal in the job id must not escape the artifact root."""
    for probe in ["../../etc/passwd", "..%2f..%2fetc", "....//"]:
        response = client.get(f"/api/v1/analyses/{probe}/score")
        assert response.status_code in {404, 400, 422}
