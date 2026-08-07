"""X-Wing hybrid KEM — X25519 + ML-KEM-768 with the SHA3-256 combiner.

This module is the template Quanta **vendors into a target repository** when applying
pattern P1. Two consequences follow, and both constrain what may be written here:

* It must be self-contained. The only dependency is ``cryptography`` (>= 48, which is the
  release that made ML-KEM reachable from the project's OpenSSL wheels). It must never
  import from ``quanta``, because it will live in someone else's tree.
* It must never import ``oqs``. liboqs describes itself as prototyping software whose
  algorithm security "may rapidly change"; inserting it into other people's repositories
  is a hard prohibition (ADR-003, §11.2), enforced by ``tests/security/test_forbidden_oqs.py``.

Construction follows ``draft-connolly-cfrg-xwing-kem-10`` §5. X-Wing is IND-CCA secure if
*either* component is secure, and the combiner binds the ciphertext and public key so that
the result is not the naive concatenation that would lack a proof.

.. warning::
   The combiner appends ``XWingLabel`` **last**. Technical Documentation §3.9 places it
   first; that is an error in the document. See ``docs/adr/ADR-019``. Permuting the inputs
   yields a different construction to which the X-Wing security proof does not apply, and
   the round-trip property would still pass — so this cannot be caught by testing alone.

X-Wing is an IETF draft, not an RFC, and is not FIPS-blessed (RR-5). Quanta does not claim
to have security-reviewed it; see §1.4.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

__all__ = [
    "XWING_CT_SIZE",
    "XWING_PK_SIZE",
    "XWING_SK_SIZE",
    "XWING_SS_SIZE",
    "decapsulate",
    "encapsulate",
    "generate_keypair",
]

# draft-10 §5.1 — encoding and sizes.
_MLKEM768_PK_SIZE = 1184
_MLKEM768_CT_SIZE = 1088
_MLKEM768_SEED_SIZE = 64  # d ‖ z, what MLKEM768PrivateKey.from_seed_bytes expects
_X25519_SIZE = 32

#: X-Wing decapsulation key: a 32-byte seed, expanded on demand.
XWING_SK_SIZE = 32
#: X-Wing encapsulation key: ``pk_M ‖ pk_X``.
XWING_PK_SIZE = _MLKEM768_PK_SIZE + _X25519_SIZE  # 1216
#: X-Wing ciphertext: ``ct_M ‖ ct_X``.
XWING_CT_SIZE = _MLKEM768_CT_SIZE + _X25519_SIZE  # 1120
#: Combined shared secret, the SHA3-256 digest length.
XWING_SS_SIZE = 32

#: draft-10 §5.3 — the 6-byte ASCII domain separator, hex ``5c2e2f2f5e5c``.
_XWING_LABEL = b"\\./" + b"/^\\"


def _combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    """draft-10 §5.3. The label is appended **last** — see ADR-019."""
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + _XWING_LABEL).digest()


def _expand_decapsulation_key(
    seed: bytes,
) -> tuple[MLKEM768PrivateKey, X25519PrivateKey, bytes]:
    """Expand a 32-byte X-Wing seed into its component keys (draft-10 §5.2).

    Returns ``(sk_M, sk_X, pk_X)``; ``pk_X`` is returned because the combiner needs it on
    both the encapsulation and decapsulation sides.
    """
    if len(seed) != XWING_SK_SIZE:
        raise ValueError(f"X-Wing seed must be {XWING_SK_SIZE} bytes, got {len(seed)}")

    expanded = hashlib.shake_256(seed).digest(96)
    sk_m = MLKEM768PrivateKey.from_seed_bytes(expanded[:_MLKEM768_SEED_SIZE])
    sk_x = X25519PrivateKey.from_private_bytes(expanded[_MLKEM768_SEED_SIZE:])
    pk_x = sk_x.public_key().public_bytes_raw()
    return sk_m, sk_x, pk_x


def _raw_public_bytes(key: MLKEM768PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def generate_keypair(seed: bytes | None = None) -> tuple[bytes, bytes]:
    """Generate an X-Wing keypair.

    :param seed: Optional 32-byte seed for derandomised generation. Supplying one makes
        key generation reproducible, which the property tests rely on. When ``None``, a
        seed is drawn from the OS CSPRNG.
    :returns: ``(sk, pk)`` where ``sk`` is the 32-byte seed and ``pk`` is 1216 bytes.
    """
    if seed is None:
        import secrets

        seed = secrets.token_bytes(XWING_SK_SIZE)

    sk_m, _sk_x, pk_x = _expand_decapsulation_key(seed)
    pk_m = _raw_public_bytes(sk_m.public_key())
    return seed, pk_m + pk_x


def encapsulate(pk: bytes) -> tuple[bytes, bytes]:
    """Encapsulate against an X-Wing encapsulation key (draft-10 §5.4).

    :param pk: 1216-byte encapsulation key from :func:`generate_keypair`.
    :returns: ``(ct, ss)`` — ciphertext 1120 bytes, shared secret 32 bytes.

    .. note::
       The return order is ``(ct, ss)``, matching the shim contract in Technical
       Documentation §5.3.4. This is deliberately the *opposite* of
       ``cryptography``'s own ``MLKEM768PublicKey.encapsulate()``, which returns
       ``(shared_secret, ciphertext)``. Rewritten call sites bind against this module,
       not against the library, so the shim's contract is the one that matters — but the
       difference is a live footgun when editing this file.
    """
    if len(pk) != XWING_PK_SIZE:
        raise ValueError(f"X-Wing public key must be {XWING_PK_SIZE} bytes, got {len(pk)}")

    pk_m_bytes, pk_x_bytes = pk[:_MLKEM768_PK_SIZE], pk[_MLKEM768_PK_SIZE:]
    pk_m = MLKEM768PublicKey.from_public_bytes(pk_m_bytes)
    pk_x = X25519PublicKey.from_public_bytes(pk_x_bytes)

    # ML-KEM half. The library hands back (shared_secret, ciphertext) in that order.
    ss_m, ct_m = pk_m.encapsulate()

    # X25519 half: an ephemeral scalar whose public value *is* the ciphertext.
    ek_x = X25519PrivateKey.generate()
    ct_x = ek_x.public_key().public_bytes_raw()
    ss_x = ek_x.exchange(pk_x)

    ss = _combiner(ss_m, ss_x, ct_x, pk_x_bytes)
    return ct_m + ct_x, ss


def decapsulate(sk: bytes, ct: bytes) -> bytes:
    """Decapsulate an X-Wing ciphertext (draft-10 §5.5).

    :param sk: the 32-byte seed returned by :func:`generate_keypair`.
    :param ct: 1120-byte ciphertext.
    :returns: the 32-byte shared secret, equal to the one :func:`encapsulate` produced.
    """
    if len(ct) != XWING_CT_SIZE:
        raise ValueError(f"X-Wing ciphertext must be {XWING_CT_SIZE} bytes, got {len(ct)}")

    sk_m, sk_x, pk_x = _expand_decapsulation_key(sk)
    ct_m, ct_x = ct[:_MLKEM768_CT_SIZE], ct[_MLKEM768_CT_SIZE:]

    ss_m = sk_m.decapsulate(ct_m)
    ss_x = sk_x.exchange(X25519PublicKey.from_public_bytes(ct_x))

    return _combiner(ss_m, ss_x, ct_x, pk_x)
