"""Round eight: names behind the round-seven misses and the amended codebook (PROTOCOL-R8).

Each case is the shape of a documented API; none comes from the new held-out set.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from quanta.core.detect import detect_repository
from quanta.core.ingest import walk_repository
from quanta.core.models import CryptoSite
from quanta.core.ruleset_v2 import TLS_OPTION_SITES


def detect(tmp_path: Path, source: str) -> list[CryptoSite]:
    (tmp_path / "pkg").mkdir(exist_ok=True)
    (tmp_path / "pkg" / "mod.py").write_text(source, encoding="utf-8")
    return list(detect_repository(walk_repository(tmp_path).files, tmp_path).crypto_calls)


def by_line(sites: list[CryptoSite]) -> dict[int, list[CryptoSite]]:
    out: dict[int, list[CryptoSite]] = {}
    for s in sites:
        out.setdefault(s.line, []).append(s)
    return out


def names(sites: list[CryptoSite], line: int) -> set[str]:
    return {s.qualified_name for s in by_line(sites).get(line, [])}


def test_pycryptodome_pkcs1_v1_5_signing_and_encryption(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "from Cryptodome.Signature import PKCS1_v1_5\n"
        "from Cryptodome.Hash import SHA256\n"
        "from Cryptodome.PublicKey import RSA\n"
        "from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher\n"
        "\n"
        "def sign(pem, message):\n"
        "    key = RSA.importKey(pem)\n"
        "    h = SHA256.new(message)\n"
        "    return PKCS1_v1_5.new(key).sign(h)\n"
        "\n"
        "def wrap(pub, aes_key):\n"
        "    cipher_rsa = PKCS1_cipher.new(pub)\n"
        "    return cipher_rsa.encrypt(aes_key)\n",
    )
    assert names(found, 7) == {"Cryptodome.PublicKey.RSA.importKey"}
    assert "Cryptodome.Signature.PKCS1_v1_5.new" in names(found, 9)
    assert "Cryptodome.Signature.PKCS1_v1_5.new.sign" in names(found, 9)
    assert names(found, 12) == {"Crypto.Cipher.PKCS1_v1_5.new"}
    assert names(found, 13) == {"Crypto.Cipher.PKCS1_v1_5.new.encrypt"}
    assert all(s.quantum_vulnerable for s in by_line(found)[12])


def test_rsa_library_key_constructors(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "import rsa\nfrom rsa import encrypt, PublicKey\n"
        "k = rsa.PublicKey(n, e)\n"
        "p = PublicKey(n, e)\n"
        "c = encrypt(b'x', p)\n",
    )
    assert names(found, 3) == {"rsa.PublicKey"}
    assert names(found, 4) == {"rsa.PublicKey"}
    assert names(found, 5) == {"rsa.encrypt"}


def test_key_export_and_public_half_are_reported(tmp_path: Path) -> None:
    """PROTOCOL-R8 B2a: exporting a key and deriving its public key are units."""
    found = detect(
        tmp_path,
        "from ecdsa import SigningKey, NIST256p\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "sk = SigningKey.generate(curve=NIST256p)\n"
        "pem = sk.to_pem()\n"
        "vk_pem = sk.get_verifying_key().to_pem()\n"
        "key = rsa.generate_private_key(65537, 2048)\n"
        "pub = key.public_key()\n"
        "raw = key.private_bytes(enc, fmt, alg)\n",
    )
    assert names(found, 4) == {"ecdsa.SigningKey.generate.to_pem"}
    assert names(found, 5) == {
        "ecdsa.SigningKey.generate.get_verifying_key",
        "ecdsa.SigningKey.generate.get_verifying_key.to_pem",
    }
    lines = by_line(found)
    assert lines[7][0].category == "key_loading"
    assert lines[8][0].qualified_name.endswith(".private_bytes")


def test_export_names_on_unrelated_objects_are_not_reported(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "import hashlib\n\ndef f(model, frame):\n"
        "    model.to_string()\n    frame.as_dict()\n    model.public_key()\n",
    )
    assert found == []


def test_tls_context_settings_followed_and_not(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "import ssl\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.load_cert_chain('c.pem', 'k.pem')\n"
        "\n"
        "def server(context):\n"
        "    context.load_verify_locations(cafile='ca.pem')\n"
        "    context.set_ciphers('ECDHE+AESGCM')\n",
    )
    assert {s.category for s in found if s.line in (3, 6, 7)} == {"tls"}
    assert {3, 6, 7} <= set(by_line(found))


def test_joserfc_tokens_and_keys(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "from joserfc import jwt\n"
        "from joserfc.jwk import RSAKey, KeySet, OctKey\n"
        "key = RSAKey.generate_key(2048)\n"
        "token = jwt.encode({'alg': 'RS256'}, {'sub': 'a'}, key)\n"
        "jwks = KeySet([key]).as_dict()\n"
        "data = key.as_dict(private=False)\n"
        "secret = OctKey.generate_key(256)\n",
    )
    assert names(found, 3) == {"joserfc.jwk.RSAKey.generate_key"}
    assert names(found, 4) == {"joserfc.jwt.encode"}
    assert "joserfc.jwk.KeySet" in names(found, 5)
    assert names(found, 6) == {"joserfc.jwk.RSAKey.generate_key.as_dict"}
    assert not by_line(found)[7][0].scored


def test_pyaes_modes(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "import pyaes\n"
        "aes = pyaes.AESModeOfOperationCTR(key)\n"
        "out = aes.encrypt(data)\n"
        "ecb = pyaes.AESModeOfOperationECB(key)\n",
    )
    lines = by_line(found)
    assert lines[2][0].algorithms == ("AES", "MODE-CTR")
    assert lines[3][0].qualified_name == "pyaes.AESModeOfOperationCTR.encrypt"
    assert lines[4][0].weak


def test_clients_are_tls_sites_only_with_a_tls_option(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "import ssl, aiohttp, aiomqtt, redis\n"
        "ctx = ssl.create_default_context()\n"
        "a = aiohttp.TCPConnector(ssl=ctx)\n"
        "b = aiohttp.TCPConnector(limit=10)\n"
        "c = aiomqtt.Client('broker', tls_context=ctx)\n"
        "d = redis.Redis(host='h', ssl=True)\n"
        "e = redis.Redis(host='h', ssl=False)\n"
        "f = aiohttp.TCPConnector(ssl=None)\n",
    )
    lines = by_line(found)
    assert lines[3][0].qualified_name == "aiohttp.TCPConnector"
    assert lines[3][0].category == "tls"
    assert not lines[3][0].scored
    assert 4 not in lines
    assert lines[5][0].qualified_name == "aiomqtt.Client"
    assert lines[6][0].qualified_name == "redis.Redis"
    assert 7 not in lines
    assert 8 not in lines


@pytest.mark.parametrize("name", sorted(TLS_OPTION_SITES))
def test_tls_option_names_resolve(name: str) -> None:
    parts = name.split(".")
    for cut in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:cut]))
        except ImportError:
            continue
        for attr in parts[cut:]:
            assert hasattr(obj, attr), f"{name} does not resolve"
            obj = getattr(obj, attr)
        return
    pytest.skip(f"{parts[0]} is not installed (use --extra rulecheck)")


def test_coverage_ignores_methods_after_a_result_method(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text(
        "import hashlib\nx = hashlib.md5(b'a').hexdigest().upper()\n", encoding="utf-8"
    )
    result = detect_repository(walk_repository(tmp_path).files, tmp_path)
    assert result.api_unmatched == 0
    assert not result.unmatched_names
