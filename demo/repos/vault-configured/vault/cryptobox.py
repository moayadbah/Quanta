"""Shared helpers. In this variant it holds no cryptography at all.

The scattered build reaches the primitives from six separate modules, so there is
nothing for a wrapper to do.
"""

NONCE_BYTES = 12
KEY_BYTES = 32


def split_nonce(sealed: bytes) -> tuple[bytes, bytes]:
    return sealed[:NONCE_BYTES], sealed[NONCE_BYTES:]


def check_key(key: bytes) -> bytes:
    if len(key) != KEY_BYTES:
        raise ValueError("key must be 32 bytes")
    return key
