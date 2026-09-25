"""Cryptography used by this package, in one place, with hash choices read from settings.

Demo variant "configured" (Master Plan 8.8 and T2.1). Same eight calls as the scattered
and facade variants. The four hash choices come from the environment, so changing the
digest is a deployment change, not a code change (NIST CSWP 39 policy/mechanism
separation). AES-GCM and X25519 stay fixed in code, which is true of the application.
"""

from __future__ import annotations

import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def aead_aesgcm_aes(*args, **kwargs):
    """Was AESGCM at vault/store.py:12."""
    return AESGCM(*args, **kwargs)


def hashes_hash_sha2_256(*args, **kwargs):
    """Was hashes.Hash at vault/integrity.py:7."""
    return hashes.Hash(*args, algorithm=getattr(hashes, os.getenv("VAULT_DIGEST", "SHA256"))(), **kwargs)


def hkdf_hkdf_sha2_256(*args, **kwargs):
    """Was HKDF at vault/tokens.py:10."""
    return HKDF(*args, algorithm=getattr(hashes, os.getenv("VAULT_DIGEST", "SHA256"))(), **kwargs)


def hmac_new_sha2_256(*args, **kwargs):
    """Was hmac.new at vault/backup.py:9."""
    return hmac.new(*args, digestmod=os.getenv("VAULT_MAC_DIGEST", "sha256"), **kwargs)


def pbkdf2_pbkdf2hmac_sha2_256(*args, **kwargs):
    """Was PBKDF2HMAC at vault/passwords.py:10."""
    return PBKDF2HMAC(*args, algorithm=getattr(hashes, os.getenv("VAULT_DIGEST", "SHA256"))(), **kwargs)


def x25519privatekey_from_private_bytes_x25519(*args, **kwargs):
    """Was x25519.X25519PrivateKey.from_private_bytes at vault/sessions.py:12."""
    return x25519.X25519PrivateKey.from_private_bytes(*args, **kwargs)


def x25519privatekey_generate_x25519(*args, **kwargs):
    """Was x25519.X25519PrivateKey.generate at vault/sessions.py:7."""
    return x25519.X25519PrivateKey.generate(*args, **kwargs)


def x25519publickey_from_public_bytes_x25519(*args, **kwargs):
    """Was x25519.X25519PublicKey.from_public_bytes at vault/sessions.py:13."""
    return x25519.X25519PublicKey.from_public_bytes(*args, **kwargs)
