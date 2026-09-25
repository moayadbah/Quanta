"""The first load: pages arrive with their text, assets are versioned and cached (round six)."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from quanta.web import assets
from quanta.web.app import create_app


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(tmp_path / "artifacts", tmp_path / "quanta.db"))


def test_every_page_is_sent_with_its_text_in_the_readers_language(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        for path in ("/", "/workspace.html", "/privacy.html"):
            english = client.get(path).text
            # No element that holds a string is left empty for a script to fill later.
            assert not re.search(r'data-t="[^"]+"></', english), path
            assert '<html lang="en" dir="ltr">' in english
            arabic = client.get(path, cookies={"quanta-language": "ar"}).text
            assert '<html lang="ar" dir="rtl">' in arabic
            assert client.get(path + "?lang=ar").text.count('dir="rtl"') >= 1
        home = client.get("/").text
        assert "Find every cryptographic call" in home


def test_pages_vary_by_language_and_are_revalidated(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        page = client.get("/")
        assert page.headers["cache-control"] == "private, no-cache"
        assert "Cookie" in page.headers["vary"]


def test_assets_are_versioned_immutable_and_correctly_typed(tmp_path: Path) -> None:
    build = assets.build_id()
    with _client(tmp_path) as client:
        home = client.get("/").text
        assert f"/_v/{build}/site.css" in home
        for path, kind in (
            ("site.css", "text/css"),
            ("landing.mjs", "text/javascript"),
            ("brand/fonts/inter-400-latin.woff2", "font/woff2"),
            ("brand/fonts/readex-pro-arabic.woff2", "font/woff2"),
            ("brand/horizon-hero.webp", "image/webp"),
            ("content/site.json", "application/json"),
        ):
            response = client.get(f"/_v/{build}/{path}")
            assert response.status_code == 200, path
            assert response.headers["content-type"].startswith(kind), path
            assert "immutable" in response.headers["cache-control"], path
        # A page from an older deploy gets today's file, never cached under the old key.
        stale = client.get("/_v/000000000000/site.css")
        assert stale.status_code == 200 and "immutable" not in stale.headers["cache-control"]
        assert client.get(f"/_v/{build}/../../app.py").status_code == 404


def test_the_first_screen_fonts_and_modules_are_preloaded(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        english = client.get("/").text
        arabic = client.get("/?lang=ar").text
        assert "inter-display-medium-latin.woff2" in english
        assert "readex-pro-arabic.woff2" not in english
        assert "readex-pro-arabic.woff2" in arabic
        workspace = client.get("/workspace.html").text
        for module in ("workspace.mjs", "i18n.mjs", "chrome.mjs", "account.mjs"):
            assert f'rel="modulepreload" href="/_v/{assets.build_id()}/{module}"' in workspace


def test_the_font_css_has_metric_matched_fallbacks() -> None:
    css = (assets.STATIC_DIR / "site.css").read_text(encoding="utf-8")
    assert "@import" not in css
    for family in ("Inter Fallback", "Inter Display Fallback", "Readex Fallback"):
        block = re.search(rf'font-family: "{family}";[^}}]*', css)
        assert block and "size-adjust" in block.group(0) and "ascent-override" in block.group(0)
    assert css.count("font-display: optional") >= 8


def test_public_home_data_is_cacheable_and_private_data_is_not(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        for path in ("/api/v1/standards", "/api/v1/sample"):
            response = client.get(path)
            assert response.status_code == 200
            assert response.headers["cache-control"].startswith("public, max-age=300"), path
        assert client.get("/api/v1/workspace").headers["cache-control"] == "private, no-store"
        assert client.get("/auth/session").headers["cache-control"] == "private, no-store"
