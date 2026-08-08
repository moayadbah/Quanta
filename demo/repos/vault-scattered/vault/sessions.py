"""Session key agreement. Calls the key exchange directly."""

from cryptography.hazmat.primitives.asymmetric import x25519


def new_keypair() -> tuple[bytes, bytes]:
    private = x25519.X25519PrivateKey.generate()
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


def agree(private_bytes: bytes, peer_public: bytes) -> bytes:
    private = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    peer = x25519.X25519PublicKey.from_public_bytes(peer_public)
    return private.exchange(peer)
