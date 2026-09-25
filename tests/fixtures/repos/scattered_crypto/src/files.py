"""Ground truth: 1 crypto_call (hmac.new with a literal digest, shipped code)."""

import hmac


def sign(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, "sha256").digest()
