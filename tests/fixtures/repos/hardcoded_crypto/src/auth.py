"""Ground truth: 5 crypto_call sites, algorithm hard-coded at every one.

This is the low-agility shape — crypto invoked directly from application code with the
algorithm named as a literal, no wrapper, no configuration.
"""

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def legacy_digest(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()  # crypto_call, weak


def token_mac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.md5).digest()  # crypto_call, weak


def derive(shared: bytes) -> bytes:
    kdf = HKDF(  # crypto_call
        algorithm=hashes.SHA256(),  # algo_literal
        length=32,
        salt=None,
        info=b"handshake",
    )
    return kdf.derive(shared)


def exchange() -> bytes:
    private = x25519.X25519PrivateKey.generate()  # crypto_call, quantum vulnerable
    peer = x25519.X25519PrivateKey.generate().public_key()
    return private.exchange(peer)
