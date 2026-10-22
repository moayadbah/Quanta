"""Round nine: the causes of the v8 misses on H8 (evidence/PROTOCOL-R9.md, R9-A).

Each case is the shape of a documented API; none comes from the new held-out set H9.
"""

from __future__ import annotations

from pathlib import Path

from quanta.core.detect import detect_repository
from quanta.core.ingest import walk_repository
from quanta.core.models import CryptoSite
from quanta.core.readiness import classify


def detect(tmp_path: Path, source: str) -> list[CryptoSite]:
    (tmp_path / "pkg").mkdir(exist_ok=True)
    (tmp_path / "pkg" / "mod.py").write_text(source, encoding="utf-8")
    return list(detect_repository(walk_repository(tmp_path).files, tmp_path).crypto_calls)


def names_by_line(sites: list[CryptoSite]) -> dict[int, set[str]]:
    out: dict[int, set[str]] = {}
    for s in sites:
        out.setdefault(s.line, set()).add(s.qualified_name.rsplit(".", 1)[-1])
    return out


def test_symmetric_key_generation_is_not_read_as_public_key(tmp_path: Path) -> None:
    """v8 classed Fernet.generate_key as key generation, which readiness reads as an
    asymmetric call of unknown algorithm ("review")."""
    found = detect(
        tmp_path,
        "from cryptography.fernet import Fernet\n"
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "from joserfc.jwk import OctKey\n"
        "k1 = Fernet.generate_key()\n"
        "k2 = AESGCM.generate_key(bit_length=256)\n"
        "k3 = OctKey.generate_key(256)\n",
    )
    lines = {s.line: s for s in found}
    assert {4, 5, 6} <= set(lines)
    for line in (4, 5, 6):
        assert classify(lines[line]).status == "safe", line


def test_dh_from_numbers_to_shared_key(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "from cryptography.hazmat.primitives.asymmetric import dh\n"
        "def ard(p, g, sk):\n"
        "    param_nums = dh.DHParameterNumbers(p=p, g=g)\n"
        "    server_public = dh.DHPublicNumbers(sk, param_nums).public_key()\n"
        "    params = param_nums.parameters()\n"
        "    private_key = params.generate_private_key()\n"
        "    shared = private_key.exchange(server_public)\n"
        "    public_key = private_key.public_key()\n"
        "    y = public_key.public_numbers().y\n",
    )
    by_line = names_by_line(found)
    assert {"DHPublicNumbers", "public_key"} <= by_line[4]
    assert "parameters" in by_line[5]
    assert "generate_private_key" in by_line[6]
    assert "exchange" in by_line[7]
    assert "public_key" in by_line[8]
    assert "public_numbers" in by_line[9]
    assert all(s.quantum_vulnerable for s in found if s.line == 7)


def test_a_certificate_built_in_one_chain_is_followed(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "from cryptography import x509\n"
        "from cryptography.hazmat.primitives import hashes, serialization\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "cert = (\n"
        "    x509.CertificateBuilder()\n"
        "    .subject_name(name)\n"
        "    .public_key(key.public_key())\n"
        "    .sign(key, hashes.SHA256())\n"
        ")\n"
        "pem = cert.public_bytes(serialization.Encoding.PEM)\n",
    )
    by_line = names_by_line(found)
    assert "CertificateBuilder" in by_line[6]
    assert by_line[8] == {"public_key"}  # the key's public half, not the builder setter
    assert "sign" in by_line[9]  # reported where `.sign` is written
    assert "public_bytes" in by_line[11]


def test_a_class_attribute_bound_through_the_class_name(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "import jwt\n"
        "class JwtAuth:\n"
        "    _jwks_client = None\n"
        "    def __init__(self, url):\n"
        "        JwtAuth._jwks_client = jwt.PyJWKClient(url)\n"
        "    def check(self, token):\n"
        "        return self._jwks_client.get_signing_key_from_jwt(token)\n",
    )
    assert "get_signing_key_from_jwt" in names_by_line(found)[7]


def test_tls_upgrades_and_settings_on_unfollowed_objects(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "import ssl\n"
        "def go(server, conn, context, transport, options):\n"
        "    server.starttls()\n"
        "    conn.start_tls_s()\n"
        "    context.set_alpn_protocols(['h2'])\n"
        "    transport.startTLS(options)\n"
        "    ssl.match_hostname(cert, 'example.org')\n",
    )
    by_line = names_by_line(found)
    assert {3, 4, 5, 6, 7} <= set(by_line)
    assert {s.category for s in found} == {"tls"}


def test_passlib_and_asyncssh_methods_on_followed_objects(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "import asyncssh\n"
        "from passlib.context import CryptContext\n"
        "pwd = CryptContext(schemes=['bcrypt'])\n"
        "h = pwd.hash('secret')\n"
        "key = asyncssh.generate_private_key('ssh-rsa')\n"
        "pem = key.export_private_key()\n",
    )
    by_line = names_by_line(found)
    assert "hash" in by_line[4]
    assert "export_private_key" in by_line[6]


def test_tls_libraries_and_options(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "import trio, urllib.request, kafka, ldap3\n"
        "from twisted.internet.ssl import optionsForClientTLS\n"
        "from twisted.internet.endpoints import wrapClientTLS\n"
        "from tornado.httpserver import HTTPServer\n"
        "s = trio.SSLStream(stream, ssl_context=ctx)\n"
        "e = wrapClientTLS(optionsForClientTLS('h'), endpoint)\n"
        "h = HTTPServer(app, ssl_options=ctx)\n"
        "h2 = HTTPServer(app)\n"
        "d = urllib.request.urlopen(url, context=ctx)\n"
        "d2 = urllib.request.urlopen(url)\n"
        "p = kafka.KafkaProducer(ssl_context=ctx)\n"
        "v = ldap3.Server('h', use_ssl=True)\n",
    )
    by_line = names_by_line(found)
    assert by_line[5] == {"SSLStream"}
    assert by_line[6] == {"wrapClientTLS", "optionsForClientTLS"}
    assert by_line[7] == {"HTTPServer"}
    assert 8 not in by_line
    assert by_line[9] == {"urlopen"}
    assert 10 not in by_line
    assert by_line[11] == {"KafkaProducer"}
    assert by_line[12] == {"Server"}


def test_stdlib_crypto_reached_through_a_star_import(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "from helpers import *\n"
        "def sign(secret, msg):\n"
        "    return hmac.new(secret, msg, digestmod=hashlib.sha256).hexdigest()\n"
        "def digest(data):\n"
        "    hashlib = load()\n"
        "    return hashlib.md5(data)\n",
    )
    by_line = names_by_line(found)
    assert by_line[3] == {"new"}
    assert 6 not in by_line  # a local name called hashlib is not the module


def test_start_tls_needs_a_followed_object(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "import ssl\nasync def up(stream, ctx):\n    return await stream.start_tls(ctx)\n",
    )
    assert found == []


def test_a_base_class_is_not_a_site(tmp_path: Path) -> None:
    found = detect(
        tmp_path,
        "import ssl\n"
        "from twisted.internet.ssl import DefaultOpenSSLContextFactory\n"
        "class Factory(DefaultOpenSSLContextFactory):\n"
        "    pass\n"
        "class Ctx(ssl.SSLContext):\n"
        "    pass\n",
    )
    assert found == []
