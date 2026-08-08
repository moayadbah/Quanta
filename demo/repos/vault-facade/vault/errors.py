"""Vault error types."""


class VaultError(Exception):
    """Base error."""


class NotFound(VaultError):
    """No such document."""


class Denied(VaultError):
    """Caller is not permitted."""
