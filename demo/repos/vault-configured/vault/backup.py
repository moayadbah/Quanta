"""Backup manifests. Calls the MAC directly."""

import hmac

from vault import models
from vault import _crypto_facade


def sign(key: bytes, manifest: models.Manifest) -> bytes:
    mac = _crypto_facade.hmac_new_sha2_256(key, manifest.to_bytes())
    return mac.digest()


def check(key: bytes, manifest: models.Manifest, tag: bytes) -> bool:
    return hmac.compare_digest(sign(key, manifest), tag)
