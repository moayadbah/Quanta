"""Runtime settings."""

import os


def storage_root() -> str:
    return os.getenv("VAULT_ROOT", "/var/lib/vault")


def max_document_bytes() -> int:
    return int(os.getenv("VAULT_MAX_BYTES", "1048576"))


def retention_days() -> int:
    return int(os.getenv("VAULT_RETENTION_DAYS", "30"))
