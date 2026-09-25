"""Blob storage. Calls the AEAD directly."""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault import models
from vault import _crypto_facade


def seal(key: bytes, blob: models.Blob) -> bytes:
    nonce = os.urandom(12)
    aead = _crypto_facade.aead_aesgcm_aes(key)
    return nonce + aead.encrypt(nonce, blob.payload, blob.aad)
