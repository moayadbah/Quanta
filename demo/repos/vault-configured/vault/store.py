"""Blob storage. Reaches the AEAD through the insulation layer."""

from vault import cryptobox, models


def seal(key: bytes, blob: models.Blob) -> bytes:
    sealed, _tag = cryptobox.seal(key, blob.payload, blob.aad)
    return sealed
