"""Crypto ruleset v1 (§9.5) — data, not code.

A versioned list matched against ``QualifiedNameProvider`` output. The ruleset is
versioned because detection results are only reproducible relative to it, which is why
:data:`~quanta.version.CRYPTO_RULESET_VERSION` appears in the provenance triple: the same
repository at the same commit can legitimately yield different findings under a different
ruleset, and an artifact that cannot say which one produced it is not reproducible.

Editing any set here is a ruleset change. Bump ``CRYPTO_RULESET_VERSION`` when you do —
the analysis cache keys on it, so a stale version silently serves stale findings.
"""

from __future__ import annotations

from typing import Final

from quanta.version import CRYPTO_RULESET_VERSION

__all__ = [
    "ALGORITHM_LITERALS",
    "CRYPTO_QUALIFIED_NAMES",
    "CRYPTO_RULESET_VERSION",
    "QUANTUM_VULNERABLE",
    "WEAK_ALGORITHMS",
    "classify_algorithm",
    "is_crypto_name",
    "patch_contains_forbidden_import",
]


CRYPTO_QUALIFIED_NAMES: Final[frozenset[str]] = frozenset(
    {
        # asymmetric
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
        "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key",
        "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate",
        "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate",
        "cryptography.hazmat.primitives.asymmetric.dh.generate_parameters",
        # symmetric + AEAD
        "cryptography.hazmat.primitives.ciphers.Cipher",
        "cryptography.hazmat.primitives.ciphers.aead.AESGCM",
        "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305",
        # KDF / MAC / hash
        "cryptography.hazmat.primitives.kdf.hkdf.HKDF",
        "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC",
        "cryptography.hazmat.primitives.hmac.HMAC",
        "cryptography.hazmat.primitives.hashes.Hash",
        # stdlib and common third parties
        "hashlib.md5",
        "hashlib.sha1",
        "hashlib.sha256",
        "hashlib.pbkdf2_hmac",
        "hmac.new",
        "secrets.token_bytes",
        "ssl.SSLContext",
        "ssl.wrap_socket",
        "Crypto.Cipher.AES.new",  # pycryptodome
        "Crypto.PublicKey.RSA.generate",
        "nacl.public.PrivateKey",
        "nacl.secret.SecretBox",
        "jwt.encode",
        "jwt.decode",
        # Detected so a repository's existing use is visible. Never emitted (ADR-003).
        "oqs.KeyEncapsulation",
        "oqs.Signature",
    }
)

ALGORITHM_LITERALS: Final[frozenset[str]] = frozenset(
    {
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA512",
        "SHA3_256",
        "MD5",
        "AES",
        "AES128",
        "AES256",
        "ChaCha20",
        "3DES",
        "RSA",
        "ECDSA",
        "Ed25519",
        "X25519",
        "secp256r1",
        "secp384r1",
        "ML-KEM-768",
        "ML-DSA-65",
        "Kyber768",
        "Dilithium3",
    }
)

#: Broken or deprecated today, independently of quantum adversaries.
WEAK_ALGORITHMS: Final[frozenset[str]] = frozenset({"MD5", "SHA1", "3DES", "RC4"})

#: Broken by a cryptographically relevant quantum computer — the migration target set.
QUANTUM_VULNERABLE: Final[frozenset[str]] = frozenset(
    {"RSA", "ECDSA", "Ed25519", "X25519", "DH", "ECDH"}
)

#: Qualified-name prefixes that indicate a crypto module even when the exact call is not
#: enumerated above. Used only to attribute *module* relevance, never to claim a site —
#: claiming an unenumerated call would inflate recall against the benchmark.
CRYPTO_MODULE_PREFIXES: Final[tuple[str, ...]] = (
    "cryptography.",
    "Crypto.",
    "nacl.",
    "hashlib.",
    "hmac.",
    "ssl.",
    "secrets.",
    "jwt.",
    "oqs.",
)

_FORBIDDEN_EMIT_PREFIXES: Final[tuple[str, ...]] = ("import oqs", "from oqs")


def is_crypto_name(qualified_name: str) -> bool:
    """True when a resolved qualified name is an enumerated crypto call site (PROC-03)."""
    return qualified_name in CRYPTO_QUALIFIED_NAMES


def classify_algorithm(name: str) -> tuple[bool, bool]:
    """Return ``(weak, quantum_vulnerable)`` for an algorithm literal.

    Comparison is case-insensitive on a normalised form because repositories spell these
    inconsistently (``sha1``, ``SHA-1``, ``SHA_1``).
    """
    normalised = name.upper().replace("-", "").replace("_", "")
    weak = any(normalised == w.upper().replace("-", "").replace("_", "") for w in WEAK_ALGORITHMS)
    quantum = any(
        normalised == q.upper().replace("-", "").replace("_", "") for q in QUANTUM_VULNERABLE
    )
    return weak, quantum


def patch_contains_forbidden_import(diff: str) -> bool:
    """DoD-E4: does a unified diff **add** an ``oqs`` import?

    Only added lines count. A migration that *removes* an existing ``oqs`` import is
    precisely the improvement Quanta wants to make, so flagging removals would refuse the
    good outcome along with the bad one.
    """
    for line in diff.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        stripped = line[1:].strip()
        if any(stripped.startswith(prefix) for prefix in _FORBIDDEN_EMIT_PREFIXES):
            return True
    return False
