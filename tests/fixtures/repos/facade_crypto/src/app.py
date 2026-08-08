"""Application code. Reaches cryptography only through the facade — zero crypto_call sites.

Six call sites here, none of which touch a cryptographic API directly. That is the whole
point of an insulation layer, and it is what f_isolation is meant to reward.
"""

from . import crypto_facade


def login(password: bytes) -> bytes:
    return crypto_facade.digest(password)


def session_key(shared: bytes) -> bytes:
    return crypto_facade.derive(shared, b"session")


def store(key: bytes, nonce: bytes, blob: bytes) -> bytes:
    return crypto_facade.seal(key, nonce, blob)


def audit(record: bytes) -> bytes:
    return crypto_facade.digest(record)


def backup(key: bytes, nonce: bytes, blob: bytes) -> bytes:
    return crypto_facade.seal(key, nonce, blob)


def refresh(shared: bytes) -> bytes:
    return crypto_facade.derive(shared, b"refresh")
