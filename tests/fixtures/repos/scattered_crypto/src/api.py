"""Ground truth: no crypto_call. A direct dependent of both crypto modules."""

from src import files, users


def handle(key: bytes, data: bytes) -> tuple[str, bytes]:
    return users.fingerprint(data), files.sign(key, data)
