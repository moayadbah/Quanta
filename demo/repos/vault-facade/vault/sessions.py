"""Session key agreement. Reaches the key exchange through the insulation layer."""

from vault import cryptobox


def new_keypair() -> tuple[bytes, bytes]:
    public, key = cryptobox.agree(b"\x00" * 32, b"handshake")
    return key, public


def agree(private_bytes: bytes, peer_public: bytes) -> bytes:
    _public, key = cryptobox.agree(peer_public, b"session")
    return key
