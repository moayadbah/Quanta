"""Session token derivation. Reaches the KDF through the insulation layer."""

from vault import cryptobox

TOKEN_BYTES = 32


def derive(shared: bytes, purpose: bytes) -> bytes:
    _public, key = cryptobox.agree(shared, purpose)
    return key


def rotate(shared: bytes) -> bytes:
    return derive(shared, b"rotation")
