"""Ground truth: 3 crypto_call sites, all inside a single facade module.

This is the high-agility shape NIST CSWP 39 describes as an insulation layer: every
cryptographic primitive is reached through one module, so replacing the algorithm is a
small, local edit. The CDG should find a small minimum node cut here.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def digest(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())  # crypto_call + algo_literal
    h.update(data)
    return h.finalize()


def derive(shared: bytes, info: bytes) -> bytes:
    return HKDF(  # crypto_call
        algorithm=hashes.SHA256(),  # algo_literal
        length=32,
        salt=None,
        info=info,
    ).derive(shared)


def seal(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, None)  # crypto_call
