"""Password stretching. Reaches the KDF through the insulation layer."""

from vault import cryptobox


def stretch(password: bytes, salt: bytes) -> bytes:
    key, _fingerprint = cryptobox.derive_key(password, salt)
    return key


def verify(password: bytes, salt: bytes, expected: bytes) -> bool:
    return stretch(password, salt) == expected
