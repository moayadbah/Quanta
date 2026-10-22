"""Round six: public keys reached through libraries that are not cryptography libraries.

Each case is the shape of a documented API (evidence/PROTOCOL-R6.md C1). The first three are
the shapes of the round-four misses on python-tuf and open-swe.
"""

from __future__ import annotations

from pathlib import Path

from quanta.core.detect import detect_repository
from quanta.core.ingest import walk_repository


def sites(tmp_path: Path, source: str) -> set[tuple[int, str, str | None, str]]:
    (tmp_path / "pkg").mkdir(exist_ok=True)
    (tmp_path / "pkg" / "mod.py").write_text(source, encoding="utf-8")
    result = detect_repository(walk_repository(tmp_path).files, tmp_path)
    return {(s.line, s.qualified_name, s.category, s.form) for s in result.crypto_calls}


def test_securesystemslib_keys_and_their_signature_checks(tmp_path: Path) -> None:
    found = sites(
        tmp_path,
        "from securesystemslib.signer import Key\n"
        "\n"
        "def load(keyid, key_dict):\n"
        "    return Key.from_dict(keyid, key_dict)\n"
        "\n"
        "def check(keyid, key_dict, sig, payload):\n"
        "    key = Key.from_dict(keyid, key_dict)\n"
        "    key.verify_signature(sig, payload)\n",
    )
    lines = {line for line, *_ in found}
    assert {4, 7, 8} <= lines
    assert (
        8,
        "securesystemslib.signer.Key.from_dict.verify_signature",
        "signature",
        "operation",
    ) in found


def test_a_jwks_client_fetching_the_signing_key_is_an_operation(tmp_path: Path) -> None:
    found = sites(
        tmp_path,
        "from jwt import PyJWKClient\n"
        "\n"
        "_jwks: PyJWKClient | None = None\n"
        "\n"
        "def _keys() -> PyJWKClient:\n"
        "    global _jwks\n"
        "    if _jwks is None:\n"
        "        _jwks = PyJWKClient('https://example.org/jwks')\n"
        "    return _jwks\n"
        "\n"
        "def verify(token):\n"
        "    return _keys().get_signing_key_from_jwt(token)\n",
    )
    assert any(line == 12 and category == "key_loading" for line, _, category, _ in found)


def test_tls_wrapping_is_found_when_the_context_cannot_be_followed(tmp_path: Path) -> None:
    found = sites(
        tmp_path,
        "import ssl\n"
        "\n"
        "class Protocol:\n"
        "    def __init__(self, sslcontext):\n"
        "        self._sslobj = sslcontext.wrap_bio(None, None)\n",
    )
    assert (5, "ssl.SSLContext.wrap_bio", "tls", "operation") in found


def test_a_wrap_method_on_an_unrelated_object_is_still_only_tls(tmp_path: Path) -> None:
    """``wrap_socket`` and ``wrap_bio`` are names of the TLS API; other methods are not
    reported on an object that cannot be followed."""
    found = sites(
        tmp_path,
        "import ssl\n\ndef f(thing):\n    thing.sign(b'x')\n    thing.encrypt(b'x')\n",
    )
    assert found == set()


def test_ssh_google_and_openpgp_keys(tmp_path: Path) -> None:
    found = sites(
        tmp_path,
        "import asyncssh, gnupg, pgpy\n"
        "from google.oauth2 import service_account\n"
        "\n"
        "k = asyncssh.generate_private_key('ssh-ed25519')\n"
        "p = asyncssh.read_private_key('id_rsa')\n"
        "c = service_account.Credentials.from_service_account_file('sa.json')\n"
        "g = gnupg.GPG(gnupghome='/tmp/g')\n"
        "g.gen_key(g.gen_key_input())\n"
        "key, _ = pgpy.PGPKey.from_file('key.asc')\n",
    )
    by_line = {line: (name, category) for line, name, category, _ in found}
    assert by_line[4] == ("asyncssh.generate_private_key", "key_generation")
    assert by_line[5] == ("asyncssh.read_private_key", "key_loading")
    assert by_line[6][1] == "key_loading"
    assert by_line[7] == ("gnupg.GPG", "key_loading")
    assert by_line[8] == ("gnupg.GPG.gen_key", "key_generation")
    assert by_line[9] == ("pgpy.PGPKey.from_file", "key_loading")
