"""Content digests. Calls the hash directly."""

from cryptography.hazmat.primitives import hashes
from vault import _crypto_facade


def digest(payload: bytes) -> bytes:
    h = _crypto_facade.hashes_hash_sha2_256()
    h.update(payload)
    return h.finalize()


def matches(payload: bytes, expected: bytes) -> bool:
    return digest(payload) == expected
