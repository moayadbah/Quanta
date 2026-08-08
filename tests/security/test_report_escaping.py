"""§9.4 — T5 stored XSS through the report.

The report renders identifiers the repository author controls: file names, module names,
qualified names. A repository can legitimately contain a file called
``<script>alert(1)</script>.py``. Escaping that is not optional, and neither is the CSP
that backs it up if escaping ever fails.

Also asserted here: the report is genuinely self-contained, because DoD-C5 requires it to
open from ``file://`` with no network. A report that silently depended on a CDN would pass
every other test and fail the one thing it promises.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from quanta.core.detect import detect_repository
from quanta.core.graph import build_cdg
from quanta.core.ingest import walk_repository
from quanta.core.models import AnalysisMeta, Coverage, Provenance
from quanta.core.report import REPORT_SECURITY_HEADERS, render_report, safe_text
from quanta.core.score import compute_score

#: §9.4 names ``<script>alert(1)</script>`` as the fixture. A POSIX filename cannot
#: contain ``/``, so the closing tag is not expressible in a single path component — the
#: payload a repository can actually deliver is an *unclosed* tag, which browsers still
#: begin parsing as script. That is the shape tested here.
XSS = "<script>alert(1)"

#: A complete, slash-free payload. Escaping this matters just as much.
XSS_IMG = "<img src=x onerror=alert(1)>"


def _render(repo: Path) -> str:
    detection = detect_repository(walk_repository(repo).files, repo)
    graph = build_cdg(detection)
    provenance = Provenance(
        repo="owner/name",
        commit_sha="a" * 40,
        analyzer_version="0.1.0",
        crypto_ruleset_version="2026.08.01",
    )
    coverage = Coverage(
        files_scanned=detection.files_scanned,
        files_unparseable=len(detection.unparseable),
    )
    score = compute_score(detection, graph, provenance, coverage)
    meta = AnalysisMeta(
        provenance=provenance,
        started_at="2026-08-08T00:00:00Z",
        finished_at="2026-08-08T00:00:01Z",
        duration_ms=1000,
        unparseable=tuple(detection.unparseable),
    )
    return render_report(score, graph, meta)


@pytest.fixture
def xss_repo(tmp_path: Path) -> Path:
    """A repository whose *file name* carries the payload."""
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / f"{XSS}.py").write_text(
        "import hashlib\n\n\ndef f(data):\n    return hashlib.sha1(data).digest()\n"
    )
    return root


def test_script_tag_in_filename_is_escaped(xss_repo: Path) -> None:
    html = _render(xss_repo)
    assert "<script>" not in html
    assert "alert(1)" not in html or "&lt;script&gt;" in html


def test_no_executable_script_element_anywhere(xss_repo: Path) -> None:
    """No <script> element may exist in the document, escaped payload or not."""
    assert not re.search(r"<\s*script", _render(xss_repo), flags=re.IGNORECASE)


def test_no_event_handler_or_javascript_uri(xss_repo: Path) -> None:
    html = _render(xss_repo)
    assert not re.search(r"\bon(click|load|error|mouseover)\s*=", html, flags=re.IGNORECASE)
    assert "javascript:" not in html.lower()


def test_event_handler_payload_in_filename_is_escaped(tmp_path: Path) -> None:
    """A complete, slash-free payload: <img src=x onerror=alert(1)>."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / f"{XSS_IMG}.py").write_text("import hashlib\nhashlib.sha1(b'')\n")

    html = _render(root)
    assert not re.search(r"<\s*img", html, flags=re.IGNORECASE)
    assert not re.search(r"\bonerror\s*=", html, flags=re.IGNORECASE)


def test_report_is_self_contained(tmp_path: Path) -> None:
    """NFR-07: no external requests of any kind.

    Rendered from an ordinary repository, so a hostile *filename* cannot be mistaken for
    a genuine external reference.

    The SVG namespace declaration ``xmlns="http://www.w3.org/2000/svg"`` is the sole
    permitted ``http`` occurrence — it is an XML namespace identifier, never fetched.
    """
    root = tmp_path / "repo"
    root.mkdir()
    (root / "m.py").write_text("import hashlib\nhashlib.sha1(b'')\n")
    html = _render(root)
    assert "<link" not in html.lower()
    assert "src=" not in html.lower()
    assert "@import" not in html
    assert "https://" not in html

    externals = [m for m in re.findall(r"http://[^\s\"'<>]+", html) if "www.w3.org" not in m]
    assert externals == [], f"report references external resources: {externals}"


def test_payload_in_a_directory_name_is_escaped(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / f"{XSS}pkg").mkdir(parents=True)
    (root / f"{XSS}pkg" / "m.py").write_text("import hashlib\nhashlib.md5(b'')\n")
    assert not re.search(r"<\s*script", _render(root), flags=re.IGNORECASE)


def test_payload_in_an_unparseable_filename_is_escaped(tmp_path: Path) -> None:
    """Unparseable files are listed in the report by name — same exposure, same control."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / f"{XSS}broken.py").write_text("def f(\n")
    html = _render(root)
    assert not re.search(r"<\s*script", html, flags=re.IGNORECASE)
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------------------
# safe_text, the character-class reduction applied before anything is rendered
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        "'; DROP TABLE jobs;--",
        '"onload="alert(1)',
        "\x00\x01\x02",
        "‮​",
        "javascript:alert(1)",
        "{{ 7*7 }}",
        "${jndi:ldap://evil}",
    ],
)
def test_safe_text_strips_dangerous_characters(payload: str) -> None:
    cleaned = safe_text(payload)
    for ch in "\"'`{}$\\&;=%":
        assert ch not in cleaned, f"{ch!r} survived safe_text"


def test_safe_text_bounds_length() -> None:
    assert len(safe_text("a" * 5000, limit=200)) <= 200


def test_safe_text_preserves_legitimate_identifiers() -> None:
    """The control must not mangle the paths and dotted names the report exists to show."""
    for value in [
        "src/auth/token.py:88",
        "cryptography.hazmat.primitives.kdf.hkdf.HKDF",
        "pkg/_private-mod.py",
        "Class.method",
    ]:
        assert safe_text(value) == value


# ---------------------------------------------------------------------------------------
# CSP (DoD-C5)
# ---------------------------------------------------------------------------------------


def test_csp_header_is_defined_and_restrictive() -> None:
    csp = REPORT_SECURITY_HEADERS["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "script-src" not in csp, "the report needs no scripts, so none may be allowed"
    assert REPORT_SECURITY_HEADERS["X-Content-Type-Options"] == "nosniff"
    assert "X-Frame-Options" in REPORT_SECURITY_HEADERS
