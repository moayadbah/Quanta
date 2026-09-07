"""The walkthrough's copy, glossary and translations.

Every failure here is something that would otherwise be discovered live, in front of an
examining committee: a dead glossary link, a blank Arabic panel, or a technical term that
someone helpfully translated into Arabic.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from quanta.web.demo import load_content, load_glossary

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "src" / "quanta" / "web" / "static" / "guide.html"
APP_JS = ROOT / "src" / "quanta" / "web" / "static" / "app.js"

LANGS = ("en", "ar")

#: Terms that must survive untranslated inside Arabic copy. Translating any of these would
#: leave a reader unable to search for the thing being described.
PROTECTED_TERMS = (
    "CDG",
    "KEM",
    "ML-KEM",
    "ML-DSA",
    "X-Wing",
    "LibCST",
    "NetworkX",
    "CBOM",
    "minimum node cut",
    "IETF",
    "Python",
    "FIPS",
    "NIST",
)


def walk_strings(node, path=""):  # type: ignore[no-untyped-def]
    """Yield every ``{en, ar}`` pair in the tree, with its dotted path."""
    if isinstance(node, dict):
        if "en" in node or "ar" in node:
            yield path, node
            return
        for key, value in node.items():
            if key.startswith("_"):
                continue
            yield from walk_strings(value, f"{path}.{key}" if path else key)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from walk_strings(value, f"{path}.{i}")


# ---------------------------------------------------------------------------------------
# Translation completeness
# ---------------------------------------------------------------------------------------


def test_every_string_has_both_languages() -> None:
    missing = [
        f"{path} (missing {lang})"
        for path, entry in walk_strings(load_content())
        for lang in LANGS
        if not str(entry.get(lang, "")).strip()
    ]
    assert not missing, f"untranslated strings: {missing}"


def test_every_glossary_entry_has_both_languages() -> None:
    missing = []
    for key, entry in load_glossary().items():
        for field in ("what", "why"):
            for lang in LANGS:
                if not str(entry.get(field, {}).get(lang, "")).strip():
                    missing.append(f"{key}.{field}.{lang}")
    assert not missing, f"untranslated glossary fields: {missing}"


def test_every_glossary_entry_cites_a_source() -> None:
    """A follow-up question deserves a written answer behind it."""
    for key, entry in load_glossary().items():
        assert entry.get("source", "").strip(), f"{key} cites no spec section or ADR"


def test_glossary_terms_are_never_translated() -> None:
    """The heading is the term. Only its explanation changes language."""
    for key, entry in load_glossary().items():
        assert isinstance(entry["term"], str), f"{key}: term must be a single string"


# ---------------------------------------------------------------------------------------
# Term preservation inside Arabic
# ---------------------------------------------------------------------------------------


def test_protected_terms_survive_in_arabic() -> None:
    """Whenever a protected term appears in English copy, it must appear in the Arabic too."""
    offenders = []
    for path, entry in walk_strings(load_content()):
        english, arabic = entry.get("en", ""), entry.get("ar", "")
        for term in PROTECTED_TERMS:
            if term in english and term not in arabic:
                offenders.append(f"{path}: '{term}' missing from the Arabic")
    assert not offenders, offenders


def test_glossary_why_keeps_its_terms_in_arabic() -> None:
    offenders = []
    for key, entry in load_glossary().items():
        for field in ("what", "why"):
            english, arabic = entry[field]["en"], entry[field]["ar"]
            for term in PROTECTED_TERMS:
                if term in english and term not in arabic:
                    offenders.append(f"{key}.{field}: '{term}' missing from the Arabic")
    assert not offenders, offenders


# ---------------------------------------------------------------------------------------
# Markup wiring
# ---------------------------------------------------------------------------------------


def test_every_data_term_resolves_to_a_glossary_entry() -> None:
    """A dead term link is a click that does nothing, mid-presentation."""
    glossary = load_glossary()
    used = set()
    for _path, entry in walk_strings(load_content()):
        for text in entry.values():
            used |= set(re.findall(r'data-term="([a-z0-9-]+)"', str(text)))

    unknown = sorted(used - set(glossary))
    assert not unknown, f"copy references undefined terms: {unknown}"
    assert used, "no terms are marked up at all"


def test_every_data_i18n_key_exists_in_content() -> None:
    html = INDEX.read_text(encoding="utf-8")
    content = load_content()

    def resolve(path: str):  # type: ignore[no-untyped-def]
        node = content
        for part in path.split("."):
            if isinstance(node, list):
                node = node[int(part)] if part.isdigit() and int(part) < len(node) else None
            elif isinstance(node, dict):
                node = node.get(part)
            else:
                return None
            if node is None:
                return None
        return node

    missing = []
    for attr in ("data-i18n", "data-i18n-html", "data-i18n-placeholder"):
        for key in re.findall(rf'{attr}="([^"]+)"', html):
            if resolve(key) is None:
                missing.append(f"{attr}={key}")
    assert not missing, f"markup references missing content keys: {missing}"


def test_no_user_facing_sentence_is_hard_coded_in_the_markup() -> None:
    """Everything readable comes from content.json, so nothing can go untranslated.

    Scans text nodes outside script/style. Short fragments (units, punctuation, file
    names like ``score.json``) are allowed; a sentence is not.
    """
    html = INDEX.read_text(encoding="utf-8")
    html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
    html = re.sub(r"<(script|style)\b.*?</\1>", "", html, flags=re.DOTALL | re.IGNORECASE)

    text_nodes = [t.strip() for t in re.split(r"<[^>]+>", html)]
    sentences = [t for t in text_nodes if len(t.split()) >= 3 and any(c.isalpha() for c in t)]
    assert not sentences, f"hard-coded copy in index.html: {sentences}"


def test_arabic_copy_is_actually_arabic() -> None:
    """Guards against an ``ar`` value that was left as a copy of the English.

    Only prose is checked. A single token — a URL, a filename, a version string — is
    legitimately identical in both languages, and flagging those would train whoever runs
    this suite to ignore it.
    """
    identical = [
        path
        for path, entry in walk_strings(load_content())
        if entry.get("en") == entry.get("ar") and len(str(entry.get("en", "")).split()) >= 3
    ]
    assert not identical, f"Arabic is identical to English at: {identical}"


# ---------------------------------------------------------------------------------------
# Bidirectional isolation
# ---------------------------------------------------------------------------------------


def test_terms_are_rendered_inside_a_bdi_element() -> None:
    """Without <bdi>, an English term in an Arabic sentence takes its punctuation with it.

    ``CDG.`` renders as ``.CDG``. It looks broken to an Arabic reader, and it is the kind
    of thing that is invisible until someone who reads Arabic looks at the screen.
    """
    source = APP_JS.read_text(encoding="utf-8")
    assert 'createElement("bdi")' in source
    assert "renderRich" in source


def test_direction_and_language_are_switched_together() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    assert "documentElement.dir" in source
    assert "documentElement.lang" in source
    assert "rtl" in source and "ltr" in source


def test_stylesheet_uses_logical_properties_for_layout() -> None:
    """Physical margins would need a mirrored stylesheet; logical ones mirror themselves."""
    css = (ROOT / "src" / "quanta" / "web" / "static" / "app.css").read_text(encoding="utf-8")
    assert "margin-inline" in css
    assert "padding-inline" in css
    assert "border-inline-start" in css
    assert "text-align: start" in css


# ---------------------------------------------------------------------------------------
# Files on disk
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["content.json", "glossary.json"])
def test_demo_data_is_valid_json(name: str) -> None:
    with (ROOT / "demo" / name).open(encoding="utf-8") as fh:
        assert json.load(fh)


def test_all_six_acts_are_present() -> None:
    acts = load_content()["acts"]
    assert len(acts) == 6
    assert [a["id"] for a in acts] == [
        "problem",
        "inventory",
        "cdg",
        "cut",
        "verify",
        "try",
    ]


def test_act_copy_stays_short_enough_to_project() -> None:
    """B2 means short sentences. A paragraph nobody can read from the back is not B2."""
    long_ones = []
    for path, entry in walk_strings(load_content()):
        if ".body." not in path and not path.endswith(".lead"):
            continue
        plain = re.sub(r"<[^>]+>", "", str(entry["en"]))
        for sentence in re.split(r"(?<=[.?!])\s+", plain):
            if len(sentence.split()) > 26:
                long_ones.append(f"{path}: {len(sentence.split())} words")
    assert not long_ones, f"sentences too long for a projected slide: {long_ones}"
