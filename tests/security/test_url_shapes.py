"""§9.4 — malformed URL shapes are rejected (INGEST-02).

Covers the fixture list: ``../``, ``%2e%2e``, NUL bytes, unicode look-alikes,
``o/r/extra``, and empty path segments.
"""

from __future__ import annotations

import pytest

from quanta.core.ingest import parse_repo_url
from quanta.errors import Reject


@pytest.mark.parametrize(
    "url",
    [
        # Traversal, raw and percent-encoded. "%" is outside the owner/repo character
        # class, so the encoded forms never need decoding to be refused.
        "https://github.com/../etc/passwd",
        "https://github.com/o/../r",
        "https://github.com/o/..",
        "https://github.com/../r",
        "https://github.com/%2e%2e/r",
        "https://github.com/o/%2e%2e",
        "https://github.com/o/%2e%2e%2fetc",
        "https://github.com/..%2f..%2fetc",
        # Too many or too few segments.
        "https://github.com/o/r/extra",
        "https://github.com/o/r/tree/main",
        "https://github.com/o",
        "https://github.com/",
        "https://github.com",
        # Empty segments must not be silently collapsed into a valid-looking pair.
        "https://github.com//r",
        "https://github.com/o//r",
        "https://github.com///",
    ],
)
def test_malformed_paths_are_rejected(url: str) -> None:
    with pytest.raises(Reject) as exc:
        parse_repo_url(url)
    assert exc.value.code == "URL_MALFORMED"


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/o/r\x00",
        "https://github.com/o\x00/r",
        "https://github.com/o/r\x00.git",
        "https://github.com/o/r\n",
        "https://github.com/o/r\r\nHost: evil.com",
        "https://github.com/o/r\t",
        "https://github.com/o/r\x7f",
    ],
)
def test_control_characters_and_nul_are_rejected(url: str) -> None:
    """NUL and CR/LF are the standard vehicles for splitting a value across a parser."""
    with pytest.raises(Reject) as exc:
        parse_repo_url(url)
    assert exc.value.code == "URL_MALFORMED"


@pytest.mark.parametrize(
    ("url", "code"),
    [
        # Cyrillic 'а' (U+0430) in the host — visually identical, a different name.
        ("https://githuб.com/o/r", "HOST_NOT_ALLOWED"),
        ("https://githаub.com/o/r", "HOST_NOT_ALLOWED"),
        # Fullwidth solidus (U+FF0F). CPython's urlsplit refuses a netloc containing any
        # character that NFKC-normalises to '/', '?', '#', '@' or ':', so this is caught
        # at parse time rather than by the allowlist — earlier, and stricter.
        ("https://github.com／evil.com/o/r", "URL_MALFORMED"),
        # Non-ASCII in owner/repo: outside the character class.
        ("https://github.com/о/r", "URL_MALFORMED"),
        ("https://github.com/o/г", "URL_MALFORMED"),
        ("https://github.com/o/r​", "URL_MALFORMED"),
    ],
)
def test_unicode_lookalikes_are_rejected(url: str, code: str) -> None:
    with pytest.raises(Reject) as exc:
        parse_repo_url(url)
    assert exc.value.code == code


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/o/r?x=1",
        "https://github.com/o/r#frag",
        "https://github.com/o/r?",
        "https://github.com/o/r?redirect=https://evil.com",
    ],
)
def test_query_and_fragment_are_rejected(url: str) -> None:
    with pytest.raises(Reject) as exc:
        parse_repo_url(url)
    assert exc.value.code == "URL_MALFORMED"


@pytest.mark.parametrize("raw", ["", "   ", "not a url", "//github.com/o/r", "github.com/o/r"])
def test_garbage_input_is_rejected(raw: str) -> None:
    with pytest.raises(Reject):
        parse_repo_url(raw)


def test_overlong_names_are_rejected() -> None:
    """The character class is bounded at 100 — an unbounded name is a resource question."""
    with pytest.raises(Reject) as exc:
        parse_repo_url(f"https://github.com/o/{'a' * 101}")
    assert exc.value.code == "URL_MALFORMED"


def test_shell_metacharacters_are_rejected() -> None:
    """Defence in depth for T4: these can never reach git, but they never get the chance."""
    for name in ["r;rm -rf /", "r$(id)", "r`id`", "r|cat", "r&whoami", "r'", 'r"', "r r"]:
        with pytest.raises(Reject):
            parse_repo_url(f"https://github.com/o/{name}")
