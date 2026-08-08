"""Backup manifests. Calls the MAC directly."""

import hmac

from vault import models


def sign(key: bytes, manifest: models.Manifest) -> bytes:
    mac = hmac.new(key, manifest.to_bytes(), "sha256")
    return mac.digest()


def check(key: bytes, manifest: models.Manifest, tag: bytes) -> bool:
    return hmac.compare_digest(sign(key, manifest), tag)
