"""The insulation layer. Every cryptographic primitive is reached through this module.

Nothing else in the vault imports `cryptography`. Replacing an algorithm is an edit here,
not an edit in six places.
"""

import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

NONCE_BYTES = 12
KEY_BYTES = 32
ITERATIONS = 600_000


def derive_key(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """Stretch a password, and fingerprint the result for the audit log."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = kdf.derive(password)

    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(key)
    return key, fingerprint.finalize()


def seal(key: bytes, payload: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt, then authenticate the ciphertext."""
    nonce = os.urandom(NONCE_BYTES)
    sealed = nonce + AESGCM(key).encrypt(nonce, payload, aad)
    tag = hmac.new(key, sealed, "sha256").digest()
    return sealed, tag


def agree(peer_public: bytes, purpose: bytes) -> tuple[bytes, bytes]:
    """Agree a shared secret with a peer, then derive a purpose-bound key from it."""
    private = x25519.X25519PrivateKey.generate()
    peer = x25519.X25519PublicKey.from_public_bytes(peer_public)
    shared = private.exchange(peer)

    kdf = HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=None, info=purpose)
    return private.public_key().public_bytes_raw(), kdf.derive(shared)
