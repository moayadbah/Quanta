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
    _algorithm_from_name,
    detect_repository,
    module_name,
    node_id,
)
from quanta.core.ingest import walk_repository

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


def analyse(name: str) -> DetectionResult:
    repo = FIXTURES / name
    return detect_repository(walk_repository(repo).files, repo)


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
    assert len(analyse(repo).crypto_calls) == expected_calls


def test_no_crypto_fixture_yields_no_false_positives() -> None:
    """The fixture is built from near-misses: a locally defined ``sha256``, an unrelated
    class named ``Cipher``, ``base64``, and ``random``. A substring matcher fails here."""
    result = analyse("no_crypto")
    assert result.sites == []
    assert result.files_scanned == 1


def test_weak_algorithms_are_flagged() -> None:
    result = analyse("hardcoded_crypto")
    weak = {s.algorithm for s in result.sites if s.weak}
    assert weak == {"SHA1", "MD5"}


def test_quantum_vulnerable_algorithms_are_flagged() -> None:
    """X25519 is named in the *module*, not the callable — the tail is ``generate``."""
    result = analyse("hardcoded_crypto")
    vulnerable = [s for s in result.crypto_calls if s.quantum_vulnerable]
    assert len(vulnerable) == 2
    assert all(s.algorithm == "X25519" for s in vulnerable)


def test_configuration_reads_are_detected() -> None:
    result = analyse("configured_crypto")
    names = {s.qualified_name for s in result.config_reads}
    assert names == {"os.environ", "os.getenv", "settings"}


def test_config_read_nested_in_a_callee_is_found() -> None:
    """``os.getenv(...).encode()`` hides the read in the callee, not in the arguments."""
    result = analyse("configured_crypto")
    assert any(s.qualified_name == "os.getenv" for s in result.config_reads)


def test_algorithm_literals_are_detected_and_attached_to_their_site() -> None:
    result = analyse("facade_crypto")
    literals = result.algo_literals
    assert len(literals) == 2
    assert all(lit.algorithm == "SHA256" for lit in literals)
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
        found = len(analyse(repo).crypto_calls)
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
# Algorithm resolution
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("qualified_name", "expected"),
    [
        ("hashlib.sha1", "SHA1"),
        ("hashlib.md5", "MD5"),
        ("hashes.SHA256", "SHA256"),
        ("cryptography...x25519.X25519PrivateKey.generate", "X25519"),
        ("cryptography...ciphers.aead.AESGCM", "AES"),
        ("cryptography...ciphers.aead.ChaCha20Poly1305", "ChaCha20"),
        ("cryptography...asymmetric.rsa.generate_private_key", "RSA"),
        ("cryptography...hashes.Hash", None),
        ("os.getenv", None),
        ("json.dumps", None),
    ],
)
def test_algorithm_resolution(qualified_name: str, expected: str | None) -> None:
    assert _algorithm_from_name(qualified_name) == expected


def test_module_name_derivation(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "pkg" / "sub").mkdir(parents=True)
    assert module_name(root / "pkg" / "sub" / "mod.py", root) == "pkg.sub.mod"
    assert module_name(root / "pkg" / "__init__.py", root) == "pkg"
    assert module_name(root / "top.py", root) == "top"
