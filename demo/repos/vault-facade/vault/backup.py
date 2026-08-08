"""Backup manifests. Reaches the MAC through the insulation layer."""

from vault import cryptobox, models


def sign(key: bytes, manifest: models.Manifest) -> bytes:
    _sealed, tag = cryptobox.seal(key, manifest.to_bytes())
    return tag


def check(key: bytes, manifest: models.Manifest, tag: bytes) -> bool:
    return sign(key, manifest) == tag
