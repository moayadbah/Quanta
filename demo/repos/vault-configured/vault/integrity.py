"""Content digests. Reaches the hash through the insulation layer."""

from vault import cryptobox


def digest(payload: bytes) -> bytes:
    _key, fingerprint = cryptobox.derive_key(payload, b"integrity")
    return fingerprint


def matches(payload: bytes, expected: bytes) -> bool:
    return digest(payload) == expected
