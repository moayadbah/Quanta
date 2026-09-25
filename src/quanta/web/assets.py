"""Versioned static assets and the pages that reference them.

Every file in ``static/`` is also served under ``/_v/<build>/``, where ``<build>`` is a hash
of the whole directory. Those URLs never change content, so browsers and Vercel's edge keep
them for a year (``immutable``): a second visit loads nothing but the page itself. Relative
URLs inside CSS and modules (fonts, ``./i18n.mjs``) resolve under the same prefix, so one
rewrite of the page's own links versions everything it loads. A new deploy has a new hash.

Pages are served from here too: the strings of the reader's language are written into the
markup before it leaves the server, so the first paint already has its final text, in its
final font, at its final size. JavaScript then only adds behaviour.
"""

from __future__ import annotations

import hashlib
import html
import json
import mimetypes
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

STATIC_DIR = Path(__file__).resolve().parent / "static"
PAGES = ("index.html", "workspace.html", "privacy.html")
IMMUTABLE = "public, max-age=31536000, s-maxage=31536000, immutable"
REVALIDATE = "public, max-age=0, must-revalidate"

for _type, _ext in (
    ("font/woff2", ".woff2"),
    ("font/ttf", ".ttf"),
    ("image/webp", ".webp"),
    ("image/svg+xml", ".svg"),
    ("text/javascript", ".mjs"),
    ("text/css", ".css"),
):
    mimetypes.add_type(_type, _ext)


@lru_cache(maxsize=1)
def build_id() -> str:
    digest = hashlib.sha256()
    for path in sorted(STATIC_DIR.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            digest.update(path.relative_to(STATIC_DIR).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


def asset_url(relative: str) -> str:
    return f"/_v/{build_id()}/{relative.lstrip('/')}"


def static_file(relative: str) -> Path | None:
    """The file under static/ for a request path, or None (never outside the directory)."""
    if not relative or "\\" in relative or relative.startswith("/"):
        return None
    path = (STATIC_DIR / relative).resolve()
    if not path.is_file() or not path.is_relative_to(STATIC_DIR):
        return None
    if any(part.startswith(".") for part in path.relative_to(STATIC_DIR).parts):
        return None
    return path


def cache_control(relative: str) -> str:
    """Unversioned static URLs: fonts and images for a day, everything else revalidated."""
    if relative.endswith((".woff2", ".ttf", ".webp", ".png", ".svg")):
        return "public, max-age=86400"
    return REVALIDATE


# Pages ------------------------------------------------------------------------------------
#: The faces each language's first screen draws. The other language's faces are fetched
#: once the page is idle (i18n.mjs), so switching never waits for a download.
FIRST_FONTS = {
    "en": (
        "inter-400-latin.woff2",
        "inter-500-latin.woff2",
        "inter-600-latin.woff2",
        "inter-display-medium-latin.woff2",
        # The hero's hex field is drawn in this face; it must be ready when the field is.
        "geist-mono-500-latin.woff2",
    ),
    "ar": ("readex-pro-arabic.woff2", "geist-mono-500-latin.woff2"),
}
_IMPORT = re.compile(r'^\s*import\b[^;]*?\bfrom\s+"\./([\w.-]+\.mjs)"', re.MULTILINE)


def _module_graph(entry: str) -> list[str]:
    """Every module an entry script imports, directly or not, in load order."""
    seen: list[str] = []
    queue = [entry]
    while queue:
        name = queue.pop(0)
        if name in seen or not (STATIC_DIR / name).is_file():
            continue
        seen.append(name)
        queue += _IMPORT.findall((STATIC_DIR / name).read_text(encoding="utf-8"))
    return seen


def _preloads(source: str, lang: str) -> str:
    links = [
        f'<link rel="preload" href="{asset_url("brand/fonts/" + name)}" as="font" '
        'type="font/woff2" crossorigin>'
        for name in FIRST_FONTS["ar" if lang == "ar" else "en"]
    ]
    links.append(
        f'<link rel="preload" href="{asset_url("content/site.json")}" as="fetch" crossorigin>'
    )
    entry = re.search(r'<script type="module" src="([\w.-]+\.mjs)"', source)
    if entry:
        links += [
            f'<link rel="modulepreload" href="{asset_url(name)}">'
            for name in _module_graph(entry.group(1))
        ]
    return "\n  ".join(links)


_LOCAL_REF = re.compile(r'(\s(?:href|src|srcset)=")(?!/|#|https?:|data:|mailto:)([^"]+)"')
_DATA_T = re.compile(r'(<([a-zA-Z0-9]+)\b[^>]*?\sdata-t="([^"]+)"[^>]*>)(\s*)(</\2>)')
_DATA_T_ATTR = re.compile(r'<[a-zA-Z0-9]+\b[^>]*?\sdata-t-attr="([^"]+)"[^>]*>')


@lru_cache(maxsize=1)
def _strings() -> dict[str, dict[str, str]]:
    from quanta.resources import asset_path

    payload = json.loads(asset_path("content/site.json").read_text(encoding="utf-8"))
    table: dict[str, dict[str, str]] = payload["strings"]
    return table


def _text(key: str, lang: str) -> str:
    entry = _strings().get(key)
    if not entry:
        return key
    return entry.get(lang) or entry.get("en") or key


def _fill_attrs(tag: str, lang: str) -> str:
    spec = re.search(r'data-t-attr="([^"]+)"', tag)
    if spec is None:
        return tag
    for pair in spec.group(1).split(";"):
        if "=" not in pair:
            continue
        attr, key = (part.strip() for part in pair.split("=", 1))
        value = html.escape(_text(key, lang), quote=True)
        if re.search(rf'\s{attr}="[^"]*"', tag):

            def put(match: re.Match[str], text: str = value) -> str:
                return f'{match.group(1)}{text}"'

            tag = re.sub(rf'(\s{attr}=")[^"]*"', put, tag, count=1)
        else:
            tag = tag[:-1] + f' {attr}="{value}">' if not tag.endswith("/>") else tag
    return tag


@lru_cache(maxsize=16)
def render_page(name: str, lang: str, account: str = "") -> str:
    """A page with its links versioned and its text written in ``lang``."""
    source = (STATIC_DIR / name).read_text(encoding="utf-8")
    base = asset_url("")
    out = _LOCAL_REF.sub(lambda m: f'{m.group(1)}{base}{m.group(2)}"', source)
    out = _DATA_T.sub(
        lambda m: f"{m.group(1)}{html.escape(_text(m.group(3), lang))}{m.group(5)}", out
    )
    out = _DATA_T_ATTR.sub(lambda m: _fill_attrs(m.group(0), lang), out)
    direction = "rtl" if lang == "ar" else "ltr"
    out = out.replace('<html lang="en" dir="ltr">', f'<html lang="{lang}" dir="{direction}">', 1)
    title_key = re.search(r'<body[^>]*data-title-key="([^"]+)"', out)
    if title_key:
        title = html.escape(_text(title_key.group(1), lang))
        out = re.sub(r"<title>[^<]*</title>", f"<title>{title}</title>", out, count=1)
    # The build and language the page was rendered with, for the scripts.
    meta = (
        f'<meta name="quanta-build" content="{build_id()}">'
        f'<meta name="quanta-lang" content="{lang}">'
    )
    out = out.replace('<meta charset="utf-8">', '<meta charset="utf-8">' + meta, 1)
    out = out.replace("</head>", "  " + _preloads(source, lang) + "\n</head>", 1)
    if account:
        # The workspace's first screen is known on the server: show it from the first paint.
        out = out.replace("<body ", f'<body data-account="{account}" ', 1)
        block = "doors" if account == "doors" else "dashboard"
        out = out.replace(
            f'<div id="{block}" class="stack" hidden>', f'<div id="{block}" class="stack">', 1
        )
    return out


def page_language(query: str | None, cookie: str | None, accept: str | None) -> str:
    for choice in (query, cookie):
        if choice in {"en", "ar"}:
            return choice
    return "ar" if (accept or "").lower().startswith("ar") else "en"


def page_headers(extra: dict[str, Any] | None = None) -> dict[str, str]:
    headers = {"Cache-Control": "private, no-cache", "Vary": "Cookie, Accept-Language"}
    headers.update(extra or {})
    return headers


def workspace_state(page: str, account: str, login: str = "", lang: str = "en") -> str:
    """The workspace header and first screen for this visitor, drawn before it is sent."""
    if account == "doors":
        return page.replace(
            'id="signin" href="/auth/login" hidden', 'id="signin" href="/auth/login"', 1
        )
    if account == "user":
        chip = html.escape(login)
        page = page.replace(
            'id="account-chip" hidden></span>', f'id="account-chip">{chip}</span>', 1
        )
        page = page.replace('id="signout" type="button" hidden', 'id="signout" type="button"', 1)
        page = page.replace(
            'id="menu-signin" data-t="account.signin"',
            'id="menu-signin" hidden data-t="account.signin"',
            1,
        )
        page = page.replace('id="avatar-sk" hidden', 'id="avatar-sk"', 1)
        return page.replace('<div id="repos-block" hidden>', '<div id="repos-block">', 1)
    if account == "local":
        title = html.escape(_text("ws.scan_title", lang))
        return page.replace(
            '<h1 class="h1" id="welcome-title"><span class="sk sk-h1"></span></h1>',
            f'<h1 class="h1" id="welcome-title">{title}</h1>',
            1,
        )
    return page
