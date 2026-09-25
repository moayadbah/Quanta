"""Session token derivation. Calls the KDF directly."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from vault import _crypto_facade

TOKEN_BYTES = 32


def derive(shared: bytes, purpose: bytes) -> bytes:
    kdf = _crypto_facade.hkdf_hkdf_sha2_256(
        length=TOKEN_BYTES,
        salt=None,
        info=purpose,
    )
    return kdf.derive(shared)


def rotate(shared: bytes) -> bytes:
    return derive(shared, b"rotation")
