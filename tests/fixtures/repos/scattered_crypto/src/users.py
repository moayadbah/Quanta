"""Ground truth: 1 crypto_call (hashlib.sha256, literal, shipped code)."""

import hashlib


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
