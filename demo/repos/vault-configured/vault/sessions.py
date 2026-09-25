"""Session key agreement. Calls the key exchange directly."""

from cryptography.hazmat.primitives.asymmetric import x25519
from vault import _crypto_facade


def new_keypair() -> tuple[bytes, bytes]:
    private = _crypto_facade.x25519privatekey_generate_x25519()
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


def agree(private_bytes: bytes, peer_public: bytes) -> bytes:
    private = _crypto_facade.x25519privatekey_from_private_bytes_x25519(private_bytes)
    peer = _crypto_facade.x25519publickey_from_public_bytes_x25519(peer_public)
    return private.exchange(peer)
