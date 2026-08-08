"""§9.4 — T1 SSRF. Hostile URLs are rejected **before any network call**.

The ordering claim is the control, so it is tested rather than assumed: ``socket``
resolution is booby-trapped for the duration of every case. A validator that rejected the
URL only *after* resolving its host would still return the right answer while having
already leaked a DNS lookup to an attacker-chosen name — this suite fails that
implementation.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest

from quanta.core.ingest import parse_repo_url
from quanta.errors import Reject


@pytest.fixture(autouse=True)
def _no_network() -> Iterator[None]:
    """Make any DNS resolution or socket connection an immediate test failure."""

    def _boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("network access attempted during URL validation")

    originals = {
        "getaddrinfo": socket.getaddrinfo,
        "gethostbyname": socket.gethostbyname,
        "create_connection": socket.create_connection,
    }
    for attr in originals:
        setattr(socket, attr, _boom)
    try:
        yield
    finally:
        for attr, fn in originals.items():
            setattr(socket, attr, fn)


# The literal fixture list named in §9.4, plus the metadata-service address that makes
# SSRF worth ranking Critical in the first place.
HOSTILE_URLS = [
    ("http://github.com/o/r", "HOST_NOT_ALLOWED"),
    ("file:///etc/passwd", "HOST_NOT_ALLOWED"),
    ("git@github.com:owner/repo", "HOST_NOT_ALLOWED"),
    ("https://evil.com/o/r", "HOST_NOT_ALLOWED"),
    ("https://user:pw@github.com/o/r", "URL_MALFORMED"),
    ("https://github.com:8080/o/r", "URL_MALFORMED"),
    ("https://127.0.0.1/o/r", "HOST_NOT_ALLOWED"),
    ("https://169.254.169.254/o/r", "HOST_NOT_ALLOWED"),
]


@pytest.mark.parametrize(("url", "code"), HOSTILE_URLS)
def test_hostile_urls_are_rejected(url: str, code: str) -> None:
    with pytest.raises(Reject) as exc:
        parse_repo_url(url)
    assert exc.value.code == code


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/o/r",
        "https://0.0.0.0/o/r",
        "https://[::1]/o/r",
        "https://10.0.0.1/o/r",
        "https://192.168.1.1/o/r",
        "https://172.16.0.1/o/r",
        "https://metadata.google.internal/o/r",
        # Look-alike hosts: a subdomain, a suffix and a prefix of the allowed host.
        "https://github.com.evil.com/o/r",
        "https://notgithub.com/o/r",
        "https://raw.githubusercontent.com/o/r",
        "https://github.co/o/r",
    ],
)
def test_internal_and_lookalike_hosts_are_rejected(url: str) -> None:
    """An allowlist, not a denylist: none of these is github.com, so none is special-cased."""
    with pytest.raises(Reject) as exc:
        parse_repo_url(url)
    assert exc.value.code == "HOST_NOT_ALLOWED"


@pytest.mark.parametrize(
    "scheme",
    ["http", "ftp", "file", "gopher", "data", "javascript", "ssh", "git"],
)
def test_only_https_is_accepted(scheme: str) -> None:
    with pytest.raises(Reject) as exc:
        parse_repo_url(f"{scheme}://github.com/o/r")
    assert exc.value.code == "HOST_NOT_ALLOWED"


def test_the_happy_path_still_works_without_network() -> None:
    """Sanity check on the fixture: validation of a good URL must not touch the network."""
    assert parse_repo_url("https://github.com/pallets/click") == ("pallets", "click")


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/pallets/click.git", ("pallets", "click")),
        ("https://GitHub.com/pallets/click", ("pallets", "click")),
        ("https://github.com/pallets/click/", ("pallets", "click")),
    ],
)
def test_accepted_variants(url: str, expected: tuple[str, str]) -> None:
    assert parse_repo_url(url) == expected
