"""Cryptography used by this package, in one place.

Demo variant "facade" (Master Plan T2.1): the scattered variant with pattern P1 applied as
Master Plan 9.3 specifies. Each function forwards to the original call with the original
algorithm; round two verified the eight wrappers equal to the originals on seeded inputs.
Change algorithms here, not at the call sites.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hmac


def aead_aesgcm_aes(*args, **kwargs):
    """Was AESGCM at vault/store.py:12."""
    return AESGCM(*args, **kwargs)


def hashes_hash_sha2_256(*args, **kwargs):
    """Was hashes.Hash at vault/integrity.py:7."""
    return hashes.Hash(*args, algorithm=hashes.SHA256(), **kwargs)


def hkdf_hkdf_sha2_256(*args, **kwargs):
    """Was HKDF at vault/tokens.py:10."""
    return HKDF(*args, algorithm=hashes.SHA256(), **kwargs)


def hmac_new_sha2_256(*args, **kwargs):
    """Was hmac.new at vault/backup.py:9."""
    return hmac.new(*args, digestmod="sha256", **kwargs)


def pbkdf2_pbkdf2hmac_sha2_256(*args, **kwargs):
    """Was PBKDF2HMAC at vault/passwords.py:10."""
    return PBKDF2HMAC(*args, algorithm=hashes.SHA256(), **kwargs)


def x25519privatekey_from_private_bytes_x25519(*args, **kwargs):
    """Was x25519.X25519PrivateKey.from_private_bytes at vault/sessions.py:12."""
    return x25519.X25519PrivateKey.from_private_bytes(*args, **kwargs)


def x25519privatekey_generate_x25519(*args, **kwargs):
    """Was x25519.X25519PrivateKey.generate at vault/sessions.py:7."""
    return x25519.X25519PrivateKey.generate(*args, **kwargs)


def x25519publickey_from_public_bytes_x25519(*args, **kwargs):
    """Was x25519.X25519PublicKey.from_public_bytes at vault/sessions.py:13."""
    return x25519.X25519PublicKey.from_public_bytes(*args, **kwargs)
