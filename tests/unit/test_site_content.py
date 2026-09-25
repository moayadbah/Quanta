"""content/site.json holds every visible string of the web product, in English and Arabic.

A failure here is a blank label, an untranslated screen, a placeholder the page cannot
fill, or a sentence typed straight into the markup where an editor cannot reach it.
"""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import get_args

import pytest

from quanta.core.analyze import STEP_TITLES
from quanta.core.roles import Role
from quanta.core.ruleset_v2 import Category
from quanta.errors import ERROR_CODES

ROOT = Path(__file__).resolve().parents[2]
CONTENT = ROOT / "content" / "site.json"
STATIC = ROOT / "src" / "quanta" / "web" / "static"
PAGES = ("index.html", "workspace.html", "privacy.html")
SCRIPTS = ("landing.mjs", "workspace.mjs", "i18n.mjs", "chrome.mjs", "page.mjs")


@pytest.fixture(scope="module")
def strings() -> dict[str, dict[str, str]]:
    payload = json.loads(CONTENT.read_text(encoding="utf-8"))
    table: dict[str, dict[str, str]] = payload["strings"]
    return table


def used_keys() -> set[str]:
    keys: set[str] = set()
    for page in PAGES:
        html = (STATIC / page).read_text(encoding="utf-8")
        keys.update(re.findall(r'data-t="([^"]+)"', html))
        for attr in re.findall(r'data-t-attr="([^"]+)"', html):
            keys.update(pair.split("=", 1)[1].strip() for pair in attr.split(";") if "=" in pair)
        keys.update(re.findall(r'data-title-key="([^"]+)"', html))
    for script in SCRIPTS:
        source = (STATIC / script).read_text(encoding="utf-8")
        keys.update(re.findall(r'\bt\("([a-z][\w.\-]*)"', source))
        keys.update(re.findall(r'\btk\(`[^`]*`,\s*"([a-z][\w.\-]*)"', source))
        # Keys chosen by a ternary: t(cond ? "a.b" : "c.d")
        for group in re.findall(r"\bt\(([^()]*\?[^()]*)\)", source):
            keys.update(re.findall(r'"([a-z]+\.[\w.\-]+)"', group))
    return keys


def test_every_used_key_exists(strings: dict[str, dict[str, str]]) -> None:
    missing = sorted(k for k in used_keys() if "." in k and k not in strings)
    assert not missing, f"keys used by the pages but absent from content/site.json: {missing}"


def test_every_string_has_both_languages(strings: dict[str, dict[str, str]]) -> None:
    empty = [
        f"{k}.{lang}"
        for k, v in strings.items()
        for lang in ("en", "ar")
        if not v.get(lang, "").strip()
    ]
    assert not empty, f"untranslated strings: {empty}"


def test_placeholders_match_between_languages(strings: dict[str, dict[str, str]]) -> None:
    mismatched = [
        key
        for key, value in strings.items()
        if set(re.findall(r"\{(\w+)\}", value["en"])) != set(re.findall(r"\{(\w+)\}", value["ar"]))
    ]
    assert not mismatched, f"placeholders differ between en and ar: {mismatched}"


def test_open_vocabularies_are_covered(strings: dict[str, dict[str, str]]) -> None:
    """Codes the API or engine can emit, which the pages render through the file."""
    required = (
        [f"error.{code}" for code in ERROR_CODES]
        + [f"cat.{c}" for c in get_args(Category)]
        + [f"role.{r}" for r in get_args(Role)]
        + [f"step.{sid}" for sid, _ in STEP_TITLES]
        + [f"status.job.{s}" for s in ("queued", "running", "succeeded", "failed", "timeout")]
        + [f"status.score.{s}" for s in ("scored", "refused", "no_crypto_detected")]
        + [
            f"gate.{g}"
            for g in (
                "NO_SOURCE_FILES",
                "TRUNCATED_INPUT",
                "TOO_MANY_UNPARSEABLE",
                "LOW_DETECTION_COVERAGE",
                "TOO_FEW_MODULES",
            )
        ]
        + [
            f"refusal.{c}.{p}"
            for c in ("PROTOCOL_NEGOTIATED", "STORED_FORMAT_DEFAULT")
            for p in ("title", "body")
        ]
        # Readiness verdicts. Verification verdicts left the web copy in round four with
        # the verification screen (the CLI and API keep them).
        + [f"verdict.{v}" for v in ("at_risk", "in_transition", "ready", "no_crypto", "no_source")]
        + [
            f"factor.{f}.{p}"
            for f in ("call_sites", "isolation_layer", "selection_source", "propagation_depth")
            for p in ("name", "why")
        ]
        + [f"rec.{p}" for p in ("P0", "P1", "P2", "P3")]
    )
    missing = [k for k in required if k not in strings]
    assert not missing, f"missing: {missing}"


def test_english_copy_has_no_dashes(strings: dict[str, dict[str, str]]) -> None:
    dashes = "[" + chr(0x2013) + chr(0x2014) + "]"
    dashed = [k for k, v in strings.items() if re.search(dashes, v["en"] + v["ar"])]
    assert not dashed, f"em or en dash in: {dashed}"


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.found: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in {"meta", "link", "img", "input", "br", "source", "col", "path"}:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        while self.stack and self.stack.pop() != tag:
            pass

    def handle_data(self, data: str) -> None:
        text = data.strip()
        # Stage numerals (01, 02) are data, not copy.
        if text.isdigit():
            return
        if text and not (self.stack and self.stack[-1] in {"title", "script", "style"}):
            self.found.append(text)


@pytest.mark.parametrize("page", PAGES)
def test_markup_carries_keys_not_text(page: str) -> None:
    parser = _Text()
    parser.feed((STATIC / page).read_text(encoding="utf-8"))
    assert parser.found == [], f"visible text typed into {page}: {parser.found}"
