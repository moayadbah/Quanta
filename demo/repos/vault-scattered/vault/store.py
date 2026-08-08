"""Blob storage. Calls the AEAD directly."""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault import models


def seal(key: bytes, blob: models.Blob) -> bytes:
    nonce = os.urandom(12)
    aead = AESGCM(key)
    return nonce + aead.encrypt(nonce, blob.payload, blob.aad)
