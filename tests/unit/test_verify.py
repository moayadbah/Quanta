"""The verification package without Docker: install plans and trace classification.

The Docker path itself is exercised by the round-three studies (evidence/r3/trace) and by
``quanta trace`` on the vault demo; these tests pin the parts that decide what a result means.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quanta.verify.plan import install_plan
from quanta.verify.sandbox import slug
from quanta.verify.trace import check, classify


def write(root: Path, name: str, text: str) -> None:
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(text, encoding="utf-8")


def test_crypto_extras_are_installed_with_the_tests(tmp_path: Path) -> None:
    """Round two: pyjwt's tests extra alone skipped every RSA and EC test (rule 7)."""
    write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname = "x"\nrequires-python = ">=3.9"\n'
        "[project.optional-dependencies]\n"
        'tests = ["pytest"]\ncrypto = ["cryptography>=3.4"]\ndocs = ["sphinx"]\n',
    )
    plan = install_plan(tmp_path)
    assert plan.rule == "rule2:tests"
    assert plan.extras == ["tests", "crypto"]
    assert plan.command == "uv pip install --system -e '.[tests,crypto]'"


def test_a_python_version_that_excludes_312_is_unverifiable(tmp_path: Path) -> None:
    write(tmp_path, "pyproject.toml", '[project]\nname = "x"\nrequires-python = "<3.10"\n')
    plan = install_plan(tmp_path)
    assert not plan.possible
    assert plan.rule == "PYTHON_VERSION"


def test_no_packaging_is_unverifiable(tmp_path: Path) -> None:
    write(tmp_path, "app.py", "x = 1\n")
    assert install_plan(tmp_path).rule == "NO_INSTALL_METHOD"


@pytest.mark.parametrize(
    ("callee", "expected"),
    [
        ("_hashlib.openssl_sha256", "A"),
        ("_hashlib.HASH.hexdigest", None),
        ("cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.sign", "B"),
        ("hmac.compare_digest", "C"),
        ("ssl.create_default_context", "A"),
        ("ssl.SSLContext.wrap_socket", "B"),
        ("cryptography.x509.general_name.DNSName", None),
        ("cryptography.x509.extensions.Extensions.get_extension_for_class", None),
        ("cryptography.x509.base.load_pem_x509_certificate", "A"),
        ("cryptography.x509.base.CertificateSigningRequestBuilder.sign", "B"),
    ],
)
def test_classification(callee: str, expected: str | None) -> None:
    assert classify(callee) == expected


def test_check_counts_only_shipped_algorithm_lines_and_lists_misses() -> None:
    trace = [
        {"file": "app/a.py", "line": 3, "callee": "_hashlib.openssl_sha256", "count": 2},
        {"file": "app/a.py", "line": 3, "callee": "_hashlib.HASH.hexdigest", "count": 2},
        {"file": "app/b.py", "line": 9, "callee": "ssl.create_default_context", "count": 1},
        {"file": "app/c.py", "line": 4, "callee": "nacl.signing.VerifyKey", "count": 1},
        {"file": "tests/test_a.py", "line": 5, "callee": "hashlib.md5", "count": 1},
        {
            "file": "app/d.py",
            "line": 7,
            "callee": "cryptography.hazmat.primitives.hashes.SHA256",
            "count": 1,
        },
    ]
    cdg = {
        "nodes": [
            {"kind": "crypto_call", "file": "app/a.py", "line": 3},
            {"kind": "crypto_call", "file": "app/b.py", "line": 9},
            {"kind": "crypto_call", "file": "app/e.py", "line": 1},
        ]
    }
    result = check(trace, cdg)
    assert result.executed_a_lines == 3  # a.py:3, b.py:9, c.py:4 (d.py is a selector line)
    assert result.found_by_static == 2
    assert [m["file"] for m in result.missed] == ["app/c.py"]
    assert result.static_not_executed == 1
    assert not result.too_few


def test_docker_names_are_safe() -> None:
    assert slug("Some/Repo Name!") == "some-repo-name-"
    assert slug("") == "repo"
