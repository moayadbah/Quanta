"""/references: the page the poster's QR code opens. Its address, its counts and its links."""

from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from quanta.web.app import create_app

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "src" / "quanta" / "web" / "static"
PAGE = (STATIC / "references.html").read_text(encoding="utf-8")
STRINGS = json.loads((ROOT / "content" / "site.json").read_text(encoding="utf-8"))["strings"]


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(tmp_path / "artifacts", tmp_path / "quanta.db"))


def test_short_address_serves_the_page_in_both_languages(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        english = client.get("/references")
        assert english.status_code == 200
        assert "The standards, research and measurements" in english.text
        assert "Content-Security-Policy" in english.headers
        arabic = client.get("/references", cookies={"quanta-language": "ar"}).text
        assert '<html lang="ar" dir="rtl">' in arabic
        assert "المراجع" in arabic
        assert client.get("/references.html").status_code == 200


def test_counts_on_the_page_match_its_lists() -> None:
    sources = PAGE.count('<li class="ref">')
    checks = PAGE.count('<li class="check">')
    assert STRINGS["refs.stat.sources_n"]["en"] == str(sources)
    assert STRINGS["refs.stat.tests_n"]["en"] == str(checks)
    for group in re.findall(r'<section class="ref-group" id="(\w+)".*?</section>', PAGE, re.S):
        if group == "validation":
            continue
        block = PAGE.split(f'id="{group}"', 1)[1].split("</section>", 1)[0]
        assert f'<span class="num">{block.count("<li"):02d}</span>' in block


def test_every_source_links_out_over_https_and_keeps_its_title_in_both_languages() -> None:
    rows = re.findall(r'<li class="ref">(.*?)</li>', PAGE, re.S)
    assert rows
    for row in rows:
        (url,) = re.findall(r'href="([^"]+)"', row)
        assert url.startswith("https://"), url
        assert 'target="_blank" rel="noopener noreferrer"' in row
        (key,) = re.findall(r'data-t="(refs\.[\w]+\.title)"', row)
        # Source titles and dates are the originals: never translated.
        assert STRINGS[key]["en"] == STRINGS[key]["ar"]
        date = STRINGS[key.replace(".title", ".date")]["en"]
        assert re.fullmatch(r"\d{4}(-\d{2}(-\d{2})?)?", date), date


def test_footers_link_references_and_the_api_itself_stays(tmp_path: Path) -> None:
    for page in ("index.html", "privacy.html"):
        html = (STATIC / page).read_text(encoding="utf-8")
        assert 'href="/references"' in html
        assert "/api/docs" not in html
    with _client(tmp_path) as client:
        assert client.get("/api/docs").status_code == 200
