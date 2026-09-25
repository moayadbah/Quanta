"""Selector analysis and reference sites (Master Plan 7.4, 7.6, 7.7)."""

from __future__ import annotations

from pathlib import Path

from quanta.core.detect import DetectionResult, detect_repository


def detect(tmp_path: Path, source: str, name: str = "mod.py") -> DetectionResult:
    root = tmp_path / "repo"
    root.mkdir(exist_ok=True)
    (root / name).write_text(source, encoding="utf-8")
    return detect_repository([root / name], root)


def sites(result: DetectionResult) -> list:
    return [s for s in result.sites if s.kind == "crypto_call"]


def test_key_from_settings_is_not_a_selection(tmp_path: Path) -> None:
    result = detect(
        tmp_path,
        "import hmac\nfrom app import settings\nhmac.new(settings.SECRET_KEY, b'm', 'sha256')\n",
    )
    assert [s.selection for s in sites(result)] == ["literal"]
    assert result.config_reads == []


def test_callee_fixes_algorithm(tmp_path: Path) -> None:
    result = detect(tmp_path, "import hashlib\nhashlib.sha256(b'')\n")
    (site,) = sites(result)
    assert (site.selection, site.algorithm) == ("literal", "SHA2-256")


def test_env_selects_digest(tmp_path: Path) -> None:
    result = detect(
        tmp_path, "import hashlib, os\nhashlib.new(os.environ.get('D', 'sha256'), b'')\n"
    )
    assert [s.selection for s in sites(result)] == ["configured"]


def test_one_hop_function(tmp_path: Path) -> None:
    result = detect(
        tmp_path,
        "import hashlib, os\n\ndef pick():\n    return os.getenv('D', 'sha256')\n\n"
        "hashlib.new(pick())\n",
    )
    assert [s.selection for s in sites(result)] == ["configured"]


def test_registry_lookup(tmp_path: Path) -> None:
    result = detect(
        tmp_path,
        "import os\nfrom cryptography.hazmat.primitives import hashes\n"
        "REG = {'a': hashes.SHA256}\nhashes.Hash(REG[os.getenv('H', 'a')]())\n",
    )
    assert [s.selection for s in sites(result)] == ["configured"]


def test_parameter_is_forwarded(tmp_path: Path) -> None:
    result = detect(
        tmp_path,
        "from cryptography.hazmat.primitives import hashes\n\n"
        "def f(alg):\n    return hashes.Hash(alg)\n",
    )
    assert [s.selection for s in sites(result)] == ["forwarded"]


def test_free_selector_counts_once(tmp_path: Path) -> None:
    result = detect(
        tmp_path,
        "from cryptography.hazmat.primitives import hashes\n"
        "from cryptography.hazmat.primitives.asymmetric import padding\n\n"
        "def sign(key, d):\n"
        "    return key.sign(d, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),"
        " hashes.SHA256())\n",
    )
    free = sorted(s.qualified_name.rsplit(".", 1)[-1] for s in result.algo_literals if s.free)
    assert free == ["PSS", "SHA256"]


def test_reference_site(tmp_path: Path) -> None:
    result = detect(tmp_path, "import hashlib\nDIGEST = hashlib.sha1\n")
    (site,) = sites(result)
    assert (site.form, site.algorithm, site.weak) == ("reference", "SHA1", True)


def test_type_annotations_and_isinstance_are_not_sites(tmp_path: Path) -> None:
    result = detect(
        tmp_path,
        "import ssl\n\ndef f(ctx: ssl.SSLContext | None = None) -> bool:\n"
        "    return isinstance(ctx, ssl.SSLContext)\n",
    )
    assert sites(result) == []


def test_quantum_flags(tmp_path: Path) -> None:
    result = detect(
        tmp_path,
        "import jwt\nfrom cryptography.hazmat.primitives.asymmetric import dh, ec\n"
        "import nacl.public\n\n"
        "ec.generate_private_key(ec.SECP256R1())\n"
        "dh.generate_parameters(2, 2048)\n"
        "nacl.public.PrivateKey.generate()\n"
        "jwt.encode({}, 'k', algorithm='ES256')\n",
    )
    flagged = sorted(s.line for s in sites(result) if s.quantum_vulnerable)
    assert flagged == [5, 6, 7, 8]


def test_tls_and_public_key_calls_are_found(tmp_path: Path) -> None:
    """The round-two blind spots: TLS contexts, key loading and Ed25519 via PyNaCl."""
    result = detect(
        tmp_path,
        "import ssl\nimport nacl.signing\n"
        "from cryptography.hazmat.primitives import serialization\n\n"
        "ctx = ssl.create_default_context()\n"
        "key = serialization.load_pem_private_key(b'', password=None)\n"
        "vk = nacl.signing.VerifyKey(b'k')\n",
    )
    found = {s.line: s.category for s in sites(result)}
    assert found == {5: "tls", 6: "key_loading", 7: "signature"}


def test_jwt_algorithm_list_records_every_algorithm(tmp_path: Path) -> None:
    result = detect(tmp_path, "import jwt\njwt.decode('t', 'k', algorithms=['RS256', 'HS256'])\n")
    (site,) = sites(result)
    assert site.algorithms == ("RSA", "HMAC-SHA2-256")
    assert site.quantum_vulnerable


def test_coverage_counts(tmp_path: Path) -> None:
    result = detect(
        tmp_path,
        "import hashlib\nimport cryptography.hazmat.backends as b\n"
        "hashlib.sha256()\nhashlib.nonexistent_fn()\nb.default_backend()\n"
        "hashlib.sha256(b'').hexdigest()\n",
    )
    assert (result.api_matched, result.api_unmatched) == (3, 1)
    assert dict(result.unmatched_names) == {"hashlib.nonexistent_fn": 1}


def test_coverage_is_counted_in_shipped_code_only(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "test_x.py").write_text("import hashlib\nhashlib.unknown()\n")
    result = detect_repository([root / "tests" / "test_x.py"], root)
    assert (result.api_matched, result.api_unmatched) == (0, 0)
