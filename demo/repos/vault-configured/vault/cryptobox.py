"""The insulation layer, with the algorithm chosen by configuration.

Nothing else in the vault imports `cryptography`, and no algorithm name is written into
the code. Changing the digest is a deployment change, not a code change — the
policy/mechanism separation NIST CSWP 39 asks for.
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


def derive_key(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """Stretch a password, and fingerprint the result for the audit log."""
    kdf = PBKDF2HMAC(
        algorithm=getattr(hashes, os.getenv("VAULT_DIGEST", "SHA256"))(),
        length=KEY_BYTES,
        salt=salt,
        iterations=int(os.environ["VAULT_KDF_ITERATIONS"]),
    )
    key = kdf.derive(password)

    fingerprint = hashes.Hash(getattr(hashes, os.getenv("VAULT_DIGEST", "SHA256"))())
    fingerprint.update(key)
    return key, fingerprint.finalize()


def seal(key: bytes, payload: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt, then authenticate the ciphertext."""
    nonce = os.urandom(NONCE_BYTES)
    sealed = nonce + AESGCM(key).encrypt(nonce, payload, aad)
    tag = hmac.new(key, sealed, os.getenv("VAULT_MAC_DIGEST", "sha256")).digest()
    return sealed, tag


def agree(peer_public: bytes, purpose: bytes) -> tuple[bytes, bytes]:
    """Agree a shared secret with a peer, then derive a purpose-bound key from it."""
    private = x25519.X25519PrivateKey.generate()
    peer = x25519.X25519PublicKey.from_public_bytes(peer_public)
    shared = private.exchange(peer)

    kdf = HKDF(
        algorithm=getattr(hashes, os.getenv("VAULT_DIGEST", "SHA256"))(),
        length=KEY_BYTES,
        salt=None,
        info=purpose,
    )
    return private.public_key().public_bytes_raw(), kdf.derive(shared)
