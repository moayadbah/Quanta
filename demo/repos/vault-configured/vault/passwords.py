"""Password stretching. Calls the KDF directly."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from vault import _crypto_facade

ITERATIONS = 600_000


def stretch(password: bytes, salt: bytes) -> bytes:
    kdf = _crypto_facade.pbkdf2_pbkdf2hmac_sha2_256(
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password)


def verify(password: bytes, salt: bytes, expected: bytes) -> bool:
    return stretch(password, salt) == expected
