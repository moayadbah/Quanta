"""Crypto ruleset v2 (Master Plan 7.3): data, not code.

Written from the plan's tables, which were fixed before the round-two measurements that
showed ruleset v1 missing most public-key and TLS code. Nothing here was added to fit a
labelled repository; names are added only when the plan's table lists them (see
``evidence/PROTOCOL-R3.md`` I1).

Three kinds of rule:

* ``site``: a call (or a reference, 7.4) that performs or configures cryptography. It
  emits a ``crypto_call`` node.
* ``selector``: an algorithm object or constant, such as ``hashes.SHA256``. It is a
  literal selection inside a site's selector position, and a free selector elsewhere.
* ``benign``: crypto-namespace names that choose nothing (``default_backend``,
  ``hmac.compare_digest``). Recognised so they do not count as missed detections.

The table is validated when this module is imported: an alias that does not resolve
raises, so a typo cannot pass silently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

RuleKind = Literal["site", "selector", "benign"]
Category = Literal[
    "hash",
    "mac",
    "kdf",
    "cipher",
    "aead",
    "key_agreement",
    "signature",
    "key_generation",
    "key_loading",
    "certificate",
    "tls",
    "token",
    "randomness",
    "pq_kem",
    "pq_signature",
]


@dataclass(frozen=True)
class AlgorithmInfo:
    family: str
    weak: bool
    quantum_vulnerable: bool
    pq: bool


@dataclass(frozen=True)
class Rule:
    qualified_name: str
    kind: RuleKind
    category: Category
    algorithm: str | None = None
    selector_args: tuple[int | str, ...] = ()
    default_algorithm: str | None = None
    scored: bool = True


# ---------------------------------------------------------------------------------------
# 7.3.1 Canonical algorithms
# ---------------------------------------------------------------------------------------


def _algos(
    family: str, ids: str, *, weak: bool = False, qv: bool = False, pq: bool = False
) -> dict[str, AlgorithmInfo]:
    return {i: AlgorithmInfo(family, weak, qv, pq) for i in ids.split()}


ALGORITHMS: Final[dict[str, AlgorithmInfo]] = {
    **_algos("hash", "MD5 SHA1", weak=True),
    **_algos("hash", "SHA2-224 SHA2-256 SHA2-384 SHA2-512 SHA2-512-224 SHA2-512-256"),
    **_algos("hash", "SHA3-224 SHA3-256 SHA3-384 SHA3-512 SHAKE128 SHAKE256 BLAKE2B BLAKE2S SM3"),
    **_algos("mac", "HMAC CMAC POLY1305 HMAC-SHA2-256 HMAC-SHA2-384 HMAC-SHA2-512"),
    **_algos("cipher", "AES CAMELLIA SM4 CHACHA20 SALSA20 XSALSA20 FERNET"),
    **_algos("cipher", "3DES DES RC4 BLOWFISH", weak=True),
    **_algos("mode", "MODE-ECB", weak=True),
    **_algos("mode", "MODE-CBC MODE-CTR MODE-GCM MODE-CFB MODE-OFB MODE-XTS"),
    **_algos(
        "public_key",
        "RSA DSA DH ECC ECDSA ECDH ECC-P256 ECC-P384 ECC-P521 ECC-SECP256K1 ECC-BRAINPOOL",
        qv=True,
    ),
    **_algos("public_key", "X25519 X448 EDDSA-ED25519 EDDSA-ED448", qv=True),
    **_algos("kdf", "PBKDF2 SCRYPT ARGON2ID HKDF CONCATKDF X963KDF BCRYPT"),
    **_algos("kem", "ML-KEM-512 ML-KEM-768 ML-KEM-1024 MLKEM768-X25519", pq=True),
    **_algos("signature", "ML-DSA-44 ML-DSA-65 ML-DSA-87 SLH-DSA", pq=True),
    **_algos("token", "JOSE-NONE", weak=True),
}


def normalise(text: str) -> str:
    """Upper-case and drop ``-``, ``_``, space and ``/`` (7.3.1)."""
    return text.upper().replace("-", "").replace("_", "").replace(" ", "").replace("/", "")


def _aliases() -> dict[str, str]:
    table: dict[str, str] = {}

    def add(spellings: str, canonical: str) -> None:
        if canonical not in ALGORITHMS:
            raise ValueError(f"alias target {canonical!r} is not a canonical algorithm")
        for spelling in spellings.split():
            table[normalise(spelling)] = canonical

    add("MD5", "MD5")
    add("SHA1 SHA", "SHA1")
    add("BCRYPT", "BCRYPT")
    add("PBKDF2 PBKDF2SHA256 PBKDF2HMAC", "PBKDF2")
    add("SCRYPT", "SCRYPT")
    add("ARGON2 ARGON2ID", "ARGON2ID")
    add("SHA224 SHA2224", "SHA2-224")
    add("SHA256 SHA2256", "SHA2-256")
    add("SHA384 SHA2384", "SHA2-384")
    add("SHA512 SHA2512", "SHA2-512")
    add("SHA512224", "SHA2-512-224")
    add("SHA512256", "SHA2-512-256")
    for bits in ("224", "256", "384", "512"):
        add(f"SHA3{bits}", f"SHA3-{bits}")
    for same in ("SHAKE128", "SHAKE256", "BLAKE2B", "BLAKE2S", "SM3"):
        add(same, same)
    add("AES AES128 AES192 AES256", "AES")
    add("TRIPLEDES 3DES DES3 DESEDE", "3DES")
    add("DES", "DES")
    add("RC4 ARC4 ARCFOUR", "RC4")
    add("CHACHA20 CHACHA20POLY1305", "CHACHA20")
    for same in ("CAMELLIA", "SM4", "SALSA20", "XSALSA20", "BLOWFISH", "FERNET"):
        add(same, same)
    for mode in ("ECB", "CBC", "CTR", "GCM", "CFB", "OFB", "XTS"):
        add(mode, f"MODE-{mode}")
    add("RSA", "RSA")
    add("ECDSA", "ECDSA")
    add("ECDH", "ECDH")
    add("SECP256R1 P256 PRIME256V1 NISTP256", "ECC-P256")
    add("SECP384R1 P384 NISTP384", "ECC-P384")
    add("SECP521R1 P521 NISTP521", "ECC-P521")
    add("SECP256K1", "ECC-SECP256K1")
    add("X25519 CURVE25519", "X25519")
    add("X448", "X448")
    add("ED25519", "EDDSA-ED25519")
    add("ED448", "EDDSA-ED448")
    for size in ("512", "768", "1024"):
        add(f"MLKEM{size}", f"ML-KEM-{size}")
    add("KYBER512", "ML-KEM-512")
    add("KYBER768", "ML-KEM-768")
    add("KYBER1024", "ML-KEM-1024")
    add("MLDSA44 DILITHIUM2", "ML-DSA-44")
    add("MLDSA65 DILITHIUM3", "ML-DSA-65")
    add("MLDSA87 DILITHIUM5", "ML-DSA-87")
    add("HS256", "HMAC-SHA2-256")
    add("HS384", "HMAC-SHA2-384")
    add("HS512", "HMAC-SHA2-512")
    add("RS256 RS384 RS512 PS256 PS384 PS512", "RSA")
    add("ES256 ES384 ES512 ES256K", "ECDSA")
    add("EDDSA", "EDDSA-ED25519")
    return table


ALIASES: Final[dict[str, str]] = _aliases()

#: "none" is an algorithm only when it selects a token algorithm (7.3.1, last row).
TOKEN_ONLY_ALIASES: Final[dict[str, str]] = {"NONE": "JOSE-NONE"}


def canonical(spelling: str, *, token: bool = False) -> str | None:
    """Canonical algorithm id for a spelling, matched exactly after normalisation."""
    key = normalise(spelling)
    if token and key in TOKEN_ONLY_ALIASES:
        return TOKEN_ONLY_ALIASES[key]
    return ALIASES.get(key)


def _alias_or_raise(spelling: str) -> str:
    found = canonical(spelling)
    if found is None:
        raise ValueError(f"ruleset v2: {spelling!r} has no alias")
    return found


# ---------------------------------------------------------------------------------------
# 7.3.2 Rule table
# ---------------------------------------------------------------------------------------

C = "cryptography.hazmat.primitives."
CA = "cryptography.hazmat.primitives.asymmetric."

_RULES: list[Rule] = []


def _site(
    names: str | list[str],
    category: Category,
    algorithm: str | None = None,
    sel: tuple[int | str, ...] = (),
    *,
    default: str | None = None,
    scored: bool = True,
) -> None:
    for name in [names] if isinstance(names, str) else names:
        _RULES.append(Rule(name, "site", category, algorithm, sel, default, scored))


def _selector(name: str, category: Category, algorithm: str | None) -> None:
    _RULES.append(Rule(name, "selector", category, algorithm))


def _benign(names: str | list[str], category: Category) -> None:
    for name in [names] if isinstance(names, str) else names:
        _RULES.append(Rule(name, "benign", category))


# -- standard library ---------------------------------------------------------------------

for _fn in [
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "blake2b",
    "blake2s",
    "shake_128",
    "shake_256",
]:
    _site(f"hashlib.{_fn}", "hash", _alias_or_raise(_fn))
_site("hashlib.new", "hash", None, (0, "name"))
_site("hashlib.pbkdf2_hmac", "kdf", "PBKDF2", (0, "hash_name"))
_site("hashlib.scrypt", "kdf", "SCRYPT")
_site("hashlib.file_digest", "hash", None, (1, "digest"))
_site("hmac.new", "mac", "HMAC", (2, "digestmod"))
_site("hmac.digest", "mac", "HMAC", (2, "digest"))
_benign("hmac.compare_digest", "mac")
_site(
    [
        "secrets.token_bytes",
        "secrets.token_hex",
        "secrets.token_urlsafe",
        # ruleset v3: the false refusal of round three (evidence/DEVIATIONS.md 27)
        "secrets.choice",
        "secrets.randbelow",
        "secrets.randbits",
        "secrets.SystemRandom",
    ],
    "randomness",
    scored=False,
)
_benign("secrets.compare_digest", "mac")
_site("ssl.SSLContext", "tls", None, (0, "protocol"))
_site("ssl.create_default_context", "tls")
_site("ssl.wrap_socket", "tls")

# -- pyca/cryptography ----------------------------------------------------------------------

_site(C + "hashes.Hash", "hash", None, (0, "algorithm"))
for _h in [
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA512_224",
    "SHA512_256",
    "SHA3_224",
    "SHA3_256",
    "SHA3_384",
    "SHA3_512",
    "SHAKE128",
    "SHAKE256",
    "MD5",
    "BLAKE2b",
    "BLAKE2s",
    "SM3",
]:
    _selector(C + "hashes." + _h, "hash", _alias_or_raise(_h))
_site(C + "hmac.HMAC", "mac", "HMAC", (1, "algorithm"))
_site(C + "cmac.CMAC", "mac", "CMAC", (0, "algorithm"))
_site(C + "poly1305.Poly1305", "mac", "POLY1305")
_site([C + "kdf.hkdf.HKDF", C + "kdf.hkdf.HKDFExpand"], "kdf", "HKDF", (0, "algorithm"))
_site(C + "kdf.pbkdf2.PBKDF2HMAC", "kdf", "PBKDF2", (0, "algorithm"))
_site(C + "kdf.scrypt.Scrypt", "kdf", "SCRYPT")
_site(C + "kdf.argon2.Argon2id", "kdf", "ARGON2ID")
_site(C + "kdf.concatkdf.ConcatKDFHash", "kdf", "CONCATKDF", (0, "algorithm"))
_site(C + "kdf.x963kdf.X963KDF", "kdf", "X963KDF", (0, "algorithm"))
_site(C + "ciphers.Cipher", "cipher", None, (0, "algorithm", 1, "mode"))
for _a in ["AES", "AES128", "AES256", "Camellia", "ChaCha20", "SM4", "TripleDES"]:
    _selector(C + "ciphers.algorithms." + _a, "cipher", _alias_or_raise(_a))
for _m in ["CBC", "CTR", "GCM", "ECB", "CFB", "OFB", "XTS"]:
    _selector(C + "ciphers.modes." + _m, "cipher", f"MODE-{_m}")
_site(
    [C + "ciphers.aead." + a for a in ["AESGCM", "AESCCM", "AESOCB3", "AESSIV", "AESGCMSIV"]],
    "aead",
    "AES",
)
_site(C + "ciphers.aead.ChaCha20Poly1305", "aead", "CHACHA20")
_site(["cryptography.fernet.Fernet", "cryptography.fernet.MultiFernet"], "aead", "FERNET")
_site(CA + "rsa.generate_private_key", "key_generation", "RSA")
_site([CA + "rsa.RSAPublicNumbers", CA + "rsa.RSAPrivateNumbers"], "key_loading", "RSA")
for _p in ("PKCS1v15", "PSS", "OAEP"):
    _selector(CA + "padding." + _p, "signature", "RSA")
_benign(CA + "padding.MGF1", "signature")
_site(CA + "ec.generate_private_key", "key_generation", "ECC", (0, "curve"))
_site(CA + "ec.derive_private_key", "key_generation", "ECC", (1, "curve"))
_site(CA + "ec.EllipticCurvePublicKey.from_encoded_point", "key_loading", "ECC", (0, "curve"))
_site(
    [CA + "ec.EllipticCurvePublicNumbers", CA + "ec.EllipticCurvePrivateNumbers"],
    "key_loading",
    "ECC",
)
_selector(CA + "ec.ECDSA", "signature", "ECDSA")
_selector(CA + "ec.ECDH", "key_agreement", "ECDH")
for _curve, _algo in (
    ("SECP256R1", "ECC-P256"),
    ("SECP384R1", "ECC-P384"),
    ("SECP521R1", "ECC-P521"),
    ("SECP256K1", "ECC-SECP256K1"),
    ("BrainpoolP256R1", "ECC-BRAINPOOL"),
    ("BrainpoolP384R1", "ECC-BRAINPOOL"),
    ("BrainpoolP512R1", "ECC-BRAINPOOL"),
):
    _selector(CA + "ec." + _curve, "key_generation", _algo)
_site(
    [
        CA + "x25519.X25519PrivateKey.generate",
        CA + "x25519.X25519PrivateKey.from_private_bytes",
        CA + "x25519.X25519PublicKey.from_public_bytes",
    ],
    "key_agreement",
    "X25519",
)
_site(
    [
        CA + "x448.X448PrivateKey.generate",
        CA + "x448.X448PrivateKey.from_private_bytes",
        CA + "x448.X448PublicKey.from_public_bytes",
    ],
    "key_agreement",
    "X448",
)
_site(
    [
        CA + "ed25519.Ed25519PrivateKey.generate",
        CA + "ed25519.Ed25519PrivateKey.from_private_bytes",
        CA + "ed25519.Ed25519PublicKey.from_public_bytes",
    ],
    "signature",
    "EDDSA-ED25519",
)
_site(
    [
        CA + "ed448.Ed448PrivateKey.generate",
        CA + "ed448.Ed448PrivateKey.from_private_bytes",
        CA + "ed448.Ed448PublicKey.from_public_bytes",
    ],
    "signature",
    "EDDSA-ED448",
)
_site([CA + "dsa.generate_private_key", CA + "dsa.generate_parameters"], "key_generation", "DSA")
_site([CA + "dh.generate_parameters", CA + "dh.DHParameterNumbers"], "key_agreement", "DH")
for _size in ("768", "1024"):
    _site(
        [
            CA + f"mlkem.MLKEM{_size}PrivateKey.generate",
            CA + f"mlkem.MLKEM{_size}PrivateKey.from_seed_bytes",
            CA + f"mlkem.MLKEM{_size}PublicKey.from_public_bytes",
        ],
        "pq_kem",
        f"ML-KEM-{_size}",
    )
_site(
    [
        C + "serialization." + n
        for n in [
            "load_pem_private_key",
            "load_pem_public_key",
            "load_der_private_key",
            "load_der_public_key",
            "load_ssh_public_key",
            "load_ssh_private_key",
            "load_pem_parameters",
        ]
    ],
    "key_loading",
    scored=False,
)
_site(
    [
        "cryptography.x509.load_pem_x509_certificate",
        "cryptography.x509.load_der_x509_certificate",
        "cryptography.x509.CertificateBuilder",
        "cryptography.x509.CertificateSigningRequestBuilder",
        "cryptography.x509.load_pem_x509_csr",
        "cryptography.x509.load_der_x509_csr",
    ],
    "certificate",
    scored=False,
)
_benign(
    [
        C + "serialization." + n
        for n in [
            "Encoding",
            "PublicFormat",
            "PrivateFormat",
            "ParameterFormat",
            "NoEncryption",
        ]
    ],
    "key_loading",
)
_benign("cryptography.hazmat.backends.default_backend", "cipher")
_benign(C + "constant_time.bytes_eq", "mac")

# -- third-party libraries -------------------------------------------------------------------


def _pycryptodome(prefix: str) -> None:
    _site(prefix + "Cipher.AES.new", "cipher", "AES", (1, "mode"))
    for mod, algo in (("DES3", "3DES"), ("DES", "DES"), ("ARC4", "RC4"), ("Blowfish", "BLOWFISH")):
        _site(f"{prefix}Cipher.{mod}.new", "cipher", algo)
    for mod, algo in (
        ("ChaCha20", "CHACHA20"),
        ("ChaCha20_Poly1305", "CHACHA20"),
        ("Salsa20", "SALSA20"),
    ):
        _site(f"{prefix}Cipher.{mod}.new", "cipher", algo)
    _site(
        [prefix + "PublicKey.RSA." + f for f in ("generate", "import_key", "construct")],
        "key_generation",
        "RSA",
    )
    _site(
        [prefix + "PublicKey.ECC." + f for f in ("generate", "import_key", "construct")],
        "key_generation",
        "ECC",
        ("curve",),
    )
    _site(prefix + "PublicKey.DSA.generate", "key_generation", "DSA")
    _site([prefix + "Signature.pkcs1_15.new", prefix + "Signature.pss.new"], "signature", "RSA")
    _site(prefix + "Signature.DSS.new", "signature", "ECDSA")
    for mod in ("MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3_256", "BLAKE2b"):
        _site(f"{prefix}Hash.{mod}.new", "hash", _alias_or_raise(mod))
    _site(prefix + "Hash.HMAC.new", "mac", "HMAC", (2, "digestmod"))
    _site(prefix + "Protocol.KDF.PBKDF2", "kdf", "PBKDF2", ("hmac_hash_module",))
    _site(prefix + "Protocol.KDF.scrypt", "kdf", "SCRYPT")
    _site(prefix + "Protocol.KDF.HKDF", "kdf", "HKDF", (3, "hashmod"))
    _site(prefix + "Random.get_random_bytes", "randomness", scored=False)


_pycryptodome("Crypto.")
_pycryptodome("Cryptodome.")
_site(
    [
        "nacl.public.PrivateKey",
        "nacl.public.PrivateKey.generate",
        "nacl.public.Box",
        "nacl.public.SealedBox",
    ],
    "key_agreement",
    "X25519",
)
_site(
    ["nacl.signing.SigningKey", "nacl.signing.SigningKey.generate", "nacl.signing.VerifyKey"],
    "signature",
    "EDDSA-ED25519",
)
_site("nacl.secret.SecretBox", "aead", "XSALSA20")
_site(["nacl.pwhash.argon2id.kdf", "nacl.pwhash.argon2id.str"], "kdf", "ARGON2ID")
_site("nacl.hash.sha256", "hash", "SHA2-256")
_site("nacl.hash.sha512", "hash", "SHA2-512")
_site("nacl.hash.blake2b", "hash", "BLAKE2B")
_site("jwt.encode", "token", None, ("algorithm",), default="HMAC-SHA2-256")
_site("jwt.decode", "token", None, ("algorithms",))
_site(["jose.jwt.encode", "jose.jws.sign"], "token", None, ("algorithm",), default="HMAC-SHA2-256")
_site(["jose.jwt.decode", "jose.jws.verify"], "token", None, ("algorithms",))
_site("oqs.KeyEncapsulation", "pq_kem", None, (0,))
_site("oqs.Signature", "pq_signature", None, (0,))

# -- ruleset v3 (round four): names the v2 table did not list -------------------------------
# Each group is a public API of a maintained library. Names are checked against the real
# package by tests/unit/test_ruleset_names.py (``--extra rulecheck``).

# Standard library helpers that build TLS contexts or call OpenSSL directly.
_site(
    [
        "ssl._create_stdlib_context",
        "ssl._create_unverified_context",
        "ssl._create_default_https_context",
    ],
    "tls",
)
_site("_hashlib.new", "hash", None, (0, "name"))
_site("_hashlib.hmac_digest", "mac", "HMAC", (2, "digest"))
_site("_hashlib.pbkdf2_hmac", "kdf", "PBKDF2", (0, "hash_name"))
for _fn, _alg in [("md5", "MD5"), ("sha1", "SHA1"), ("sha256", "SHA2-256"), ("sha512", "SHA2-512")]:
    _site(f"_hashlib.openssl_{_fn}", "hash", _alg)
_site("hmac.HMAC", "mac", "HMAC", (2, "digestmod"))
_site("truststore.SSLContext", "tls", None, (0, "protocol"))

# pyca: key serialisation choices.
_site(C + "serialization.BestAvailableEncryption", "key_loading", scored=False)

# Password hashing: bcrypt, passlib, argon2-cffi, werkzeug, Django.
_site(["bcrypt.hashpw", "bcrypt.checkpw", "bcrypt.gensalt", "bcrypt.kdf"], "kdf", "BCRYPT")
for _scheme, _alg in [
    ("bcrypt", "BCRYPT"),
    ("bcrypt_sha256", "BCRYPT"),
    ("pbkdf2_sha256", "PBKDF2"),
    ("pbkdf2_sha512", "PBKDF2"),
    ("argon2", "ARGON2ID"),
    ("scrypt", "SCRYPT"),
    ("sha256_crypt", "SHA2-256"),
    ("sha512_crypt", "SHA2-512"),
    ("md5_crypt", "MD5"),
]:
    _site([f"passlib.hash.{_scheme}.hash", f"passlib.hash.{_scheme}.verify"], "kdf", _alg)
_site("passlib.context.CryptContext", "kdf", None, ("schemes",))
_site(
    ["argon2.PasswordHasher", "argon2.low_level.hash_secret", "argon2.low_level.hash_secret_raw"],
    "kdf",
    "ARGON2ID",
)
_site(
    ["werkzeug.security.generate_password_hash", "werkzeug.security.check_password_hash"],
    "kdf",
    None,
    (1, "method"),
    default="SCRYPT",
)
_site(
    ["django.contrib.auth.hashers.make_password", "django.contrib.auth.hashers.check_password"],
    "kdf",
    None,
    (2, "hasher"),
    default="PBKDF2",
)

# Signing tokens: Django signing, itsdangerous, jwcrypto, Authlib, PyJWT key fetching.
_site(
    [
        "django.core.signing.dumps",
        "django.core.signing.loads",
        "django.core.signing.Signer",
        "django.core.signing.TimestampSigner",
    ],
    "mac",
    "HMAC",
    ("algorithm",),
    default="SHA2-256",
)
_site(
    [
        "itsdangerous.Signer",
        "itsdangerous.TimestampSigner",
        "itsdangerous.Serializer",
        "itsdangerous.URLSafeSerializer",
        "itsdangerous.URLSafeTimedSerializer",
        "itsdangerous.TimedSerializer",
    ],
    "mac",
    "HMAC",
    ("digest_method",),
    default="SHA1",
)
_site("jwcrypto.jwk.JWK.generate", "key_generation", None, ("kty",))
_site(
    ["jwcrypto.jwk.JWK", "jwcrypto.jwk.JWK.from_pem", "jwcrypto.jwk.JWK.from_json"],
    "key_loading",
    scored=False,
)
_site(["jwcrypto.jws.JWS", "jwcrypto.jwt.JWT"], "token", None, ("header",))
_site(
    [
        "authlib.jose.jwt.encode",
        "authlib.jose.jwt.decode",
        "authlib.jose.JsonWebSignature",
        "authlib.jose.JsonWebToken",
    ],
    "token",
)
_site("jwt.PyJWKClient", "key_loading", scored=False)
_site(
    [
        CA + "rsa.rsa_recover_prime_factors",
        CA + "rsa.rsa_crt_dmp1",
        CA + "rsa.rsa_crt_dmq1",
        CA + "rsa.rsa_crt_iqmp",
    ],
    "key_loading",
    "RSA",
    scored=False,
)

# pyOpenSSL.
_site("OpenSSL.SSL.Context", "tls", None, (0, "method"))
_site("OpenSSL.crypto.PKey", "key_generation")
_site(
    ["OpenSSL.crypto.load_privatekey", "OpenSSL.crypto.load_publickey"],
    "key_loading",
    scored=False,
)
_site(["OpenSSL.crypto.load_certificate", "OpenSSL.crypto.X509"], "certificate", scored=False)

# SSH keys (paramiko).
for _cls, _alg in [
    ("RSAKey", "RSA"),
    ("ECDSAKey", "ECDSA"),
    ("Ed25519Key", "EDDSA-ED25519"),
    ("DSSKey", "DSA"),
]:
    _site(
        [
            f"paramiko.{_cls}",
            f"paramiko.{_cls}.from_private_key_file",
            f"paramiko.{_cls}.from_private_key",
        ],
        "key_loading",
        _alg,
    )
    if _cls != "Ed25519Key":
        _site(f"paramiko.{_cls}.generate", "key_generation", _alg)

# Elliptic-curve and RSA libraries: python-ecdsa, coincurve, eth-keys, python-rsa.
_site("ecdsa.SigningKey.generate", "key_generation", "ECDSA", ("curve",), default="ECC-P256")
_site(
    [
        "ecdsa.SigningKey.from_string",
        "ecdsa.SigningKey.from_pem",
        "ecdsa.SigningKey.from_der",
        "ecdsa.VerifyingKey.from_string",
        "ecdsa.VerifyingKey.from_pem",
        "ecdsa.VerifyingKey.from_der",
    ],
    "key_loading",
    "ECDSA",
    ("curve",),
)
for _curve, _alg in [
    ("SECP256k1", "ECC-SECP256K1"),
    ("NIST256p", "ECC-P256"),
    ("NIST384p", "ECC-P384"),
    ("NIST521p", "ECC-P521"),
]:
    _selector(f"ecdsa.{_curve}", "key_generation", _alg)
_site(["coincurve.PrivateKey", "coincurve.PublicKey"], "key_loading", "ECC-SECP256K1")
_site(
    ["eth_keys.keys.PrivateKey", "eth_keys.keys.PublicKey", "eth_keys.KeyAPI"],
    "key_loading",
    "ECC-SECP256K1",
)
# One-time passwords (HMAC-based, RFC 4226 and 6238) and Ethereum accounts (secp256k1).
_site(["pyotp.TOTP", "pyotp.HOTP"], "mac", "HMAC", ("digest",), default="SHA1")
_site(
    [
        "eth_account.Account.from_key",
        "eth_account.Account.create",
        "eth_account.Account.sign_message",
        "eth_account.Account.sign_transaction",
        "eth_account.Account.recover_message",
    ],
    "signature",
    "ECC-SECP256K1",
)

# TLS set up through a protocol client: the key exchange happens here. Inventory only,
# and these modules are not coverage prefixes (most of their calls are not cryptography).
_site(
    [
        "smtplib.SMTP_SSL",
        "imaplib.IMAP4_SSL",
        "poplib.POP3_SSL",
        "ftplib.FTP_TLS",
        "http.client.HTTPSConnection",
        "grpc.ssl_channel_credentials",
        "grpc.ssl_server_credentials",
        "grpc.aio.secure_channel",
        "grpc.secure_channel",
    ],
    "tls",
    scored=False,
)
_site("rsa.newkeys", "key_generation", "RSA")
_site(["rsa.sign", "rsa.verify"], "signature", "RSA")
_site(["rsa.encrypt", "rsa.decrypt"], "key_agreement", "RSA")
_site(["rsa.PrivateKey.load_pkcs1", "rsa.PublicKey.load_pkcs1"], "key_loading", "RSA")


def _index(rules: list[Rule]) -> dict[str, Rule]:
    index: dict[str, Rule] = {}
    for rule in rules:
        if rule.qualified_name in index:
            raise ValueError(f"ruleset v2: duplicate rule {rule.qualified_name}")
        if rule.algorithm is not None and rule.algorithm not in ALGORITHMS:
            raise ValueError(f"ruleset v2: unknown algorithm {rule.algorithm}")
        index[rule.qualified_name] = rule
    return index


RULES: Final[dict[str, Rule]] = _index(_RULES)
SITE_RULES: Final[dict[str, Rule]] = {n: r for n, r in RULES.items() if r.kind == "site"}
SELECTOR_RULES: Final[dict[str, Rule]] = {n: r for n, r in RULES.items() if r.kind == "selector"}
BENIGN_RULES: Final[dict[str, Rule]] = {n: r for n, r in RULES.items() if r.kind == "benign"}

#: Prefixes that mark a qualified name as a call into a cryptography library (7.5).
CRYPTO_MODULE_PREFIXES: Final[tuple[str, ...]] = (
    "cryptography.",
    "Crypto.",
    "Cryptodome.",
    "nacl.",
    "hashlib.",
    "hmac.",
    "ssl.",
    "secrets.",
    "jwt.",
    "jose.",
    "oqs.",
    # ruleset v3 (round four)
    "_hashlib.",
    "truststore.",
    "bcrypt.",
    "passlib.",
    "argon2.",
    "werkzeug.security.",
    "django.contrib.auth.hashers.",
    "django.core.signing.",
    "itsdangerous.",
    "jwcrypto.",
    "authlib.jose.",
    "OpenSSL.",
    "paramiko.RSAKey",
    "paramiko.ECDSAKey",
    "paramiko.Ed25519Key",
    "paramiko.DSSKey",
    "ecdsa.",
    "coincurve.",
    "eth_keys.",
    "eth_account.Account",
    "pyotp.",
    "rsa.",
)

#: A method called on the result of a matched call chooses no algorithm (7.5 correction).
#: The first five are the round-two correction; the rest are the codebook's object
#: operations (PROTOCOL B4), added in round three after the vault demo showed
#: ``AESGCM(key).encrypt(...)`` counted as a miss (evidence/DEVIATIONS.md 15).
RESULT_METHODS: Final[frozenset[str]] = frozenset(
    {"digest", "hexdigest", "update", "finalize", "copy"}
    | {"sign", "verify", "encrypt", "decrypt", "exchange", "derive", "encryptor", "decryptor"}
    | {"public_key", "private_bytes", "public_bytes"}
)


def algorithm_info(algorithm: str | None) -> AlgorithmInfo | None:
    return ALGORITHMS.get(algorithm) if algorithm else None
