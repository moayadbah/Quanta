"""Content digests. Calls the hash directly."""

from cryptography.hazmat.primitives import hashes


def digest(payload: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(payload)
    return h.finalize()


def matches(payload: bytes, expected: bytes) -> bool:
    return digest(payload) == expected
