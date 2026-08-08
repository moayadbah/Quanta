"""Ground truth: 2 crypto_call sites, algorithm selected from configuration.

This is the policy/mechanism separation NIST CSWP 39 names as an agility determinant:
the algorithm is a configuration read, not a literal, so swapping it is a config change.
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

settings = {"digest": "SHA256"}


def _algorithm():
    return getattr(hashes, os.getenv("QUANTA_DIGEST", "SHA256"))()


def derive_key(secret: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(  # crypto_call
        algorithm=_algorithm(),
        length=32,
        salt=salt,
        iterations=int(os.environ["KDF_ITERATIONS"]),  # config_read
    )
    return kdf.derive(secret)


def expand(shared: bytes) -> bytes:
    return HKDF(  # crypto_call
        algorithm=_algorithm(),
        length=int(settings["length"]),  # config_read
        salt=None,
        info=os.getenv("HKDF_INFO", "").encode(),  # config_read
    ).derive(shared)
