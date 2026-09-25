"""Detection against synthetic fixtures with known ground truth (§11.1 step 5).

Precision and recall are reported **separately** here, as DoD-C2 requires. A single
"accuracy" number over a corpus where most call sites are not cryptographic would sit
near 1.0 no matter how badly recall performed, and would conceal exactly the
false-negative rate Python static analysis is known to produce.

These fixtures are a stand-in, not a substitute, for the frozen benchmark: they measure
the detector against code written by the same people who wrote the detector. The real
figure comes from the hand-labelled corpus in Phase 1.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quanta.core.detect import (
    DetectionResult,
    detect_repository,
    module_name,
    node_id,
)
from quanta.core.ingest import walk_repository

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


def analyse(name: str) -> DetectionResult:
    repo = FIXTURES / name
    return detect_repository(walk_repository(repo).files, repo)


def choices(result: DetectionResult) -> list:
    """Sites where an algorithm is chosen; operations on the objects are left out."""
    return [s for s in result.crypto_calls if s.form != "operation"]


# ---------------------------------------------------------------------------------------
# Ground truth per fixture
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("repo", "expected_calls"),
    [
        ("hardcoded_crypto", 5),
        ("configured_crypto", 2),
        ("facade_crypto", 3),
        ("no_crypto", 0),
    ],
)
def test_crypto_call_counts_match_ground_truth(repo: str, expected_calls: int) -> None:
    # Algorithm choices only; operations on the objects they produce are counted below.
    assert len(choices(analyse(repo))) == expected_calls


def test_operations_on_crypto_objects_are_reported_once_and_not_scored() -> None:
    """Round four: ``kdf.derive`` and ``private.exchange`` in the hardcoded fixture."""
    ops = {
        (s.line, s.qualified_name.rsplit(".", 1)[-1], s.category)
        for s in analyse("hardcoded_crypto").crypto_calls
        if s.form == "operation"
    }
    assert ops == {(30, "derive", "kdf"), (36, "exchange", "key_agreement")}
    assert all(
        not s.scored for s in analyse("hardcoded_crypto").crypto_calls if s.form == "operation"
    )


def test_no_crypto_fixture_yields_no_false_positives() -> None:
    """The fixture is built from near-misses: a locally defined ``sha256``, an unrelated
    class named ``Cipher``, ``base64``, and ``random``. A substring matcher fails here."""
    result = analyse("no_crypto")
    assert result.sites == []
    assert result.files_scanned == 1


def test_weak_algorithms_are_flagged() -> None:
    """SHA-1 at a call, and MD5 selected by ``hmac.new(key, msg, hashlib.md5)``."""
    result = analyse("hardcoded_crypto")
    weak_algorithms = {a for s in result.sites if s.weak for a in s.algorithms}
    assert {"SHA1", "MD5"} <= weak_algorithms
    assert {s.line for s in result.crypto_calls if s.weak} == {16, 20}


def test_quantum_vulnerable_algorithms_are_flagged() -> None:
    """X25519 is named in the *module*, not the callable — the tail is ``generate``."""
    result = analyse("hardcoded_crypto")
    vulnerable = [s for s in choices(result) if s.quantum_vulnerable]
    assert len(vulnerable) == 2
    assert all(s.algorithm == "X25519" for s in vulnerable)


def test_configuration_selects_the_algorithm_through_a_helper() -> None:
    """``algorithm=_algorithm()`` where ``_algorithm`` returns ``getattr(hashes, os.getenv(...))()``
    is configuration-driven (Master Plan 7.6 rules 4 to 6)."""
    result = analyse("configured_crypto")
    assert {s.selection for s in choices(result)} == {"configured"}
    assert {s.qualified_name for s in result.config_reads} == {"os.getenv"}


def test_config_reads_outside_selector_positions_are_not_selections() -> None:
    """``iterations=int(os.environ[...])`` configures a count, not an algorithm (D7)."""
    result = analyse("configured_crypto")
    assert all(s.line not in {25, 33, 35} for s in result.config_reads)


def test_algorithm_literals_are_detected_and_attached_to_their_site() -> None:
    result = analyse("facade_crypto")
    literals = result.algo_literals
    assert len(literals) == 2
    assert all(lit.algorithm == "SHA2-256" for lit in literals)
    site_ids = {s.site_id for s in result.crypto_calls}
    assert all(lit.parent_site_id in site_ids for lit in literals)


def test_enclosing_function_is_recorded() -> None:
    result = analyse("hardcoded_crypto")
    by_line = {s.line: s.enclosing_function for s in result.crypto_calls}
    assert by_line[16] == "legacy_digest"
    assert by_line[34] == "exchange"


def test_facade_application_module_has_no_crypto_calls() -> None:
    """app.py reaches cryptography only through the facade — that is the point of one."""
    result = analyse("facade_crypto")
    assert {s.file for s in result.crypto_calls} == {"src/crypto_facade.py"}


# ---------------------------------------------------------------------------------------
# Precision and recall, reported separately (DoD-C2)
# ---------------------------------------------------------------------------------------


def test_precision_and_recall_against_fixture_labels() -> None:
    labels = {
        "hardcoded_crypto": 5,
        "configured_crypto": 2,
        "facade_crypto": 3,
        "no_crypto": 0,
    }
    true_positives = 0
    false_positives = 0
    false_negatives = 0

    for repo, expected in labels.items():
        found = len(choices(analyse(repo)))
        true_positives += min(found, expected)
        false_positives += max(0, found - expected)
        false_negatives += max(0, expected - found)

    precision = true_positives / (true_positives + false_positives)
    recall = true_positives / (true_positives + false_negatives)

    assert precision >= 0.80, f"precision {precision:.2f} below DoD-C2 threshold"
    assert recall >= 0.70, f"recall {recall:.2f} below DoD-C2 threshold"


# ---------------------------------------------------------------------------------------
# Unparseable handling (PROC-02)
# ---------------------------------------------------------------------------------------


def test_unparseable_file_is_recorded_not_dropped(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "broken.py").write_text("def f(\n")
    (root / "fine.py").write_text("import hashlib\nhashlib.sha1(b'')\n")

    result = detect_repository(walk_repository(root).files, root)

    assert len(result.crypto_calls) == 1
    assert [u.file for u in result.unparseable] == ["broken.py"]
    assert "syntax" in result.unparseable[0].reason
    # Excluded from the denominator, but present in the report.
    assert result.files_scanned == 1


def test_undecodable_file_is_recorded(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "binary.py").write_bytes(b"\xff\xfe\x00\x01 not utf-8")

    result = detect_repository(walk_repository(root).files, root)
    assert len(result.unparseable) == 1
    assert result.files_scanned == 0


def test_a_broken_file_never_aborts_the_run(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for i in range(5):
        (root / f"bad{i}.py").write_text("class ???:\n")
    (root / "good.py").write_text("import hashlib\nhashlib.md5(b'')\n")

    result = detect_repository(walk_repository(root).files, root)
    assert len(result.crypto_calls) == 1
    assert len(result.unparseable) == 5


# ---------------------------------------------------------------------------------------
# Determinism (NFR-03)
# ---------------------------------------------------------------------------------------


def test_detection_is_deterministic_across_runs() -> None:
    runs = [
        [(s.site_id, s.file, s.line, s.kind) for s in analyse("hardcoded_crypto").sites]
        for _ in range(3)
    ]
    assert runs[0] == runs[1] == runs[2]


def test_site_ids_are_stable_and_position_derived() -> None:
    a = node_id("crypto_call", "src/x.py", 10, 4, "hashlib.sha1")
    b = node_id("crypto_call", "src/x.py", 10, 4, "hashlib.sha1")
    c = node_id("crypto_call", "src/x.py", 11, 4, "hashlib.sha1")
    assert a == b
    assert a != c
    assert a.startswith("crypto_call-")


# ---------------------------------------------------------------------------------------
# Algorithm resolution (ruleset v2 aliases, exact match only)
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spelling", "expected"),
    [
        ("sha1", "SHA1"),
        ("SHA-1", "SHA1"),
        ("md5", "MD5"),
        ("sha256", "SHA2-256"),
        ("SHA3_256", "SHA3-256"),
        ("secp256r1", "ECC-P256"),
        ("RS256", "RSA"),
        ("HS256", "HMAC-SHA2-256"),
        ("Kyber768", "ML-KEM-768"),
        ("sha256crypt", None),  # exact match, never a prefix
        ("json", None),
    ],
)
def test_algorithm_aliases(spelling: str, expected: str | None) -> None:
    from quanta.core.ruleset_v2 import canonical

    assert canonical(spelling) == expected


def test_module_name_derivation(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "pkg" / "sub").mkdir(parents=True)
    assert module_name(root / "pkg" / "sub" / "mod.py", root) == "pkg.sub.mod"
    assert module_name(root / "pkg" / "__init__.py", root) == "pkg"
    assert module_name(root / "top.py", root) == "top"


def test_parallel_detection_is_identical_to_sequential(tmp_path: Path) -> None:
    """Round four: large repositories are parsed by a process pool. The merged result must
    be byte-identical to the one-process result, in the same order."""
    import json

    from quanta.config import get_settings
    from quanta.core.detect import PARALLEL_MIN_FILES, result_to_json

    source = (FIXTURES / "hardcoded_crypto" / "src" / "auth.py").read_text(encoding="utf-8")
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    for i in range(PARALLEL_MIN_FILES + 2):
        (pkg / f"m{i:03d}.py").write_text(source, encoding="utf-8")
    files = walk_repository(tmp_path).files
    parallel = get_settings().model_copy(deep=True)
    parallel.analysis.parse_workers = 2
    sequential = get_settings().model_copy(deep=True)
    sequential.analysis.parse_workers = 1
    a = detect_repository(files, tmp_path, parallel)
    b = detect_repository(files, tmp_path, sequential)
    assert a.files_scanned == len(files)
    assert json.dumps(result_to_json(a), sort_keys=True) == json.dumps(
        result_to_json(b), sort_keys=True
    )


def test_non_shipped_files_without_a_crypto_library_name_are_read_not_parsed(
    tmp_path: Path,
) -> None:
    """Round four: large repositories spend most parse time on tests. A test file whose text
    names no crypto library cannot hold a finding; shipped code is always parsed."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "pkg" / "plain.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (tmp_path / "tests" / "test_plain.py").write_text(
        "def test_f():\n    assert 1\n", encoding="utf-8"
    )
    (tmp_path / "tests" / "test_hash.py").write_text(
        "import hashlib\n\ndef test_h():\n    hashlib.md5(b'x')\n", encoding="utf-8"
    )
    result = detect_repository(walk_repository(tmp_path).files, tmp_path)
    assert result.files_scanned == 3
    assert result.files_text_only == 1
    assert [s.file for s in result.crypto_calls] == ["tests/test_hash.py"]
    assert any(f.file == "pkg/plain.py" for f in result.functions)


def test_time_budget_reads_shipped_code_first_and_counts_the_rest(tmp_path: Path) -> None:
    """Round four: a huge repository stops at the parse budget instead of timing out. Shipped
    code is read first, and every file not reached is counted."""
    import time

    (tmp_path / "tests").mkdir()
    (tmp_path / "pkg").mkdir()
    for i in range(3):
        (tmp_path / "tests" / f"test_{i}.py").write_text("import hashlib\n", encoding="utf-8")
    (tmp_path / "pkg" / "core.py").write_text(
        "import hashlib\n\ndef f():\n    return hashlib.md5(b'x')\n", encoding="utf-8"
    )
    files = walk_repository(tmp_path).files
    result = detect_repository(files, tmp_path, deadline=time.monotonic() - 1)
    assert result.files_scanned == 1
    assert result.files_unread == 3 and result.source_unread == 0
    assert [s.file for s in result.crypto_calls] == ["pkg/core.py"]


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_a_repository_that_is_an_ecdsa_library_is_recognised(tmp_path: Path) -> None:
    """Round five: scanning python-ecdsa reported one quantum-vulnerable finding. A package
    that is a library the rules know, and defines what they name, implements the scheme."""
    _write(
        tmp_path,
        "src/ecdsa/keys.py",
        "class SigningKey:\n"
        "    @classmethod\n"
        "    def generate(cls, curve=None, hashfunc=None):\n"
        "        return cls()\n"
        "    def sign(self, data):\n"
        "        return b''\n"
        "    def helper(self):\n"
        "        return 1\n",
    )
    result = detect_repository(walk_repository(tmp_path).files, tmp_path)
    found = {(s.qualified_name, s.algorithm, s.form) for s in result.crypto_calls}
    assert ("ecdsa.keys.SigningKey.generate", "ECDSA", "implementation") in found
    assert ("ecdsa.keys.SigningKey.sign", "ECDSA", "implementation") in found
    assert not any(name.endswith("helper") for name, _, _ in found)
    assert all(s.quantum_vulnerable and not s.scored for s in result.crypto_calls)


def test_modular_exponentiation_named_for_rsa_is_recognised(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "toyrsa/rsa.py",
        "def encrypt(message, e, n):\n    return pow(message, e, n)\n",
    )
    _write(
        tmp_path,
        "shop/pricing.py",
        "def encrypt(value, e, n):\n    return pow(value, e, n)\n",
    )
    result = detect_repository(walk_repository(tmp_path).files, tmp_path)
    assert [(s.file, s.algorithm) for s in result.crypto_calls] == [("toyrsa/rsa.py", "RSA")]
