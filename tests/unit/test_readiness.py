"""Post-quantum readiness against published standards (round four).

The assessment must be conservative (an unseen asymmetric algorithm is never "safe"),
sourced (every milestone names a source that exists in the standards file) and
deterministic (the same code gives the same result on any day).
"""

from __future__ import annotations

from pathlib import Path

from quanta.core.analyze import analyze_path
from quanta.core.detect import detect_repository
from quanta.core.ingest import walk_repository
from quanta.core.models import Provenance
from quanta.core.readiness import Readiness, assess, classify, standards
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


def _assess(tmp_path: Path, source: str) -> Readiness:
    pkg = tmp_path / "src"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "mod.py").write_text(source, encoding="utf-8")
    result = detect_repository(walk_repository(tmp_path).files, tmp_path)
    return assess(result.sites)


def _provenance() -> Provenance:
    return Provenance(
        repo="owner/name",
        commit_sha="a" * 40,
        analyzer_version=analyzer_version(),
        crypto_ruleset_version=CRYPTO_RULESET_VERSION,
    )


def test_every_milestone_and_action_cites_a_source_in_the_file() -> None:
    data = standards()
    sources = set(data["sources"])
    for source in data["sources"].values():
        assert source["url"].startswith("https://")
        assert source["where"]
    for framework in data["frameworks"]:
        assert set(framework["sources"]) <= sources
    frameworks = {f["id"] for f in data["frameworks"]}
    for milestone in data["milestones"]:
        assert milestone["source"] in sources
        assert milestone["framework"] in frameworks


def test_hardcoded_fixture_is_at_risk_with_md5_overdue() -> None:
    readiness = analyze_path(FIXTURES / "hardcoded_crypto", _provenance()).readiness
    assert readiness is not None
    assert readiness.verdict == "at_risk"
    assert readiness.earliest_year == 2030
    assert "nist-md5" in readiness.overdue
    actions = {a.id: a for a in readiness.actions}
    assert set(actions) == {"replace_weak_now", "hybrid_key_exchange", "retire_sha1"}
    assert actions["replace_weak_now"].citations == ("src/auth.py:20",)
    assert [a.priority for a in readiness.actions] == sorted(a.priority for a in readiness.actions)


def test_no_crypto_gives_no_crypto_verdict_not_ready() -> None:
    readiness = analyze_path(FIXTURES / "no_crypto", _provenance()).readiness
    assert readiness is not None
    assert readiness.verdict == "no_crypto"
    assert readiness.actions == ()


def test_unseen_asymmetric_algorithm_is_assumed_classical(tmp_path: Path) -> None:
    readiness = _assess(
        tmp_path,
        "from cryptography.hazmat.primitives import serialization\n"
        "def load(data):\n"
        "    return serialization.load_pem_private_key(data, password=None)\n",
    )
    assert readiness.verdict == "at_risk"
    assert readiness.counts["review"] == 1
    assert {a.id for a in readiness.actions} >= {"confirm_algorithms", "pq_signatures"}


def test_hybrid_kem_is_in_transition_and_standalone_needs_hybrid() -> None:
    result = detect_repository(
        walk_repository(FIXTURES / "hardcoded_crypto").files, FIXTURES / "hardcoded_crypto"
    )
    shipped = [s for s in result.crypto_calls if s.role == "source"]
    hybrid = shipped[0].model_copy(
        update={
            "algorithm": "MLKEM768-X25519",
            "algorithms": ("MLKEM768-X25519",),
            "site_id": "synthetic-hybrid",
            "file": "src/hybrid.py",
        }
    )
    standalone = shipped[0].model_copy(
        update={
            "algorithm": "ML-KEM-768",
            "algorithms": ("ML-KEM-768",),
            "category": "pq_kem",
            "site_id": "synthetic-standalone",
            "file": "src/standalone.py",
        }
    )
    assert classify(hybrid).status == "pq"
    assert classify(hybrid).exposure == ("pq_hybrid",)
    assert "pq_standalone" in classify(standalone).exposure
    readiness = assess([*shipped, hybrid, standalone])
    assert readiness.verdict == "in_transition"
    assert "make_hybrid" in {a.id for a in readiness.actions}
    nca = next(m for m in readiness.milestones if m.id == "nca-hybrid")
    assert nca.state == "due" and nca.year is None


def test_readiness_is_byte_identical_across_runs() -> None:
    first = analyze_path(FIXTURES / "hardcoded_crypto", _provenance()).readiness
    second = analyze_path(FIXTURES / "hardcoded_crypto", _provenance()).readiness
    assert first is not None and second is not None
    assert first.model_dump_json() == second.model_dump_json()
    assert first.reference_year == int(standards()["checked"][:4])


def test_readiness_artifact_is_written(tmp_path: Path) -> None:
    from quanta.core.analyze import write_artifacts

    outcome = analyze_path(FIXTURES / "hardcoded_crypto", _provenance())
    write_artifacts(outcome, tmp_path)
    assert (tmp_path / "readiness.json").is_file()
    assert "Post-quantum readiness" in (tmp_path / "report.html").read_text(encoding="utf-8")


def test_repository_path_keeps_readiness(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Round four regression: analyze_repository rebuilt the outcome field by field and
    dropped readiness, so the web worker could not publish readiness.json."""
    import shutil

    from quanta.core import analyze
    from quanta.core.ingest import RepoMetadata

    meta = RepoMetadata(owner="o", name="r", default_branch="main", size_kb=1, commit_sha="a" * 40)

    def fake_clone(owner, name, sha, target, cfg):  # type: ignore[no-untyped-def]
        shutil.copytree(FIXTURES / "hardcoded_crypto", target)

    monkeypatch.setattr(analyze, "clone_pinned", fake_clone)
    outcome = analyze.analyze_repository("https://github.com/o/r", metadata=meta)
    assert outcome.readiness is not None
    assert outcome.readiness.verdict == "at_risk"


def test_hybrid_composed_in_one_module_is_recognised(tmp_path: Path) -> None:
    """ML-KEM-768 beside X25519 in one file is one hybrid key exchange (paramiko's
    kex_mlkem.py), not a standalone PQ algorithm plus a vulnerable exchange."""
    readiness = _assess(
        tmp_path,
        "from cryptography.hazmat.primitives.asymmetric import mlkem, x25519\n"
        "def keys():\n"
        "    a = mlkem.MLKEM768PrivateKey.generate()\n"
        "    b = x25519.X25519PrivateKey.generate()\n"
        "    return a, b\n",
    )
    assert readiness.counts["vulnerable"] == 0
    assert readiness.counts["pq"] == 2
    assert readiness.verdict == "ready"
    assert "make_hybrid" not in {a.id for a in readiness.actions}


def test_standalone_pq_in_another_module_still_needs_hybrid(tmp_path: Path) -> None:
    readiness = _assess(
        tmp_path,
        "from cryptography.hazmat.primitives.asymmetric import mlkem\n"
        "def keys():\n"
        "    return mlkem.MLKEM768PrivateKey.generate()\n",
    )
    assert "make_hybrid" in {a.id for a in readiness.actions}


def test_a_repository_with_no_python_is_not_called_crypto_free(tmp_path: Path) -> None:
    (tmp_path / "index.js").write_text("const crypto = require('crypto');\n", encoding="utf-8")
    outcome = analyze_path(tmp_path, _provenance())
    assert outcome.readiness is not None
    assert outcome.readiness.verdict == "no_source"


def test_settings_build_without_a_home_directory(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The analyzer scrubs its environment; on Windows that removes USERPROFILE. Large files
    are parsed in a child that builds Settings there, and failed (exit 1) before round four."""
    from quanta.config import Settings

    def no_home() -> Path:
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(Path, "home", staticmethod(no_home))
    assert Settings().db.name == "quanta.db"


def test_readiness_says_when_shipped_code_was_not_all_read() -> None:
    assert assess([], files_scanned=5, source_unread=2).complete is False
    assert assess([], files_scanned=5).complete is True


def test_nist_112_bit_deprecation_applies_to_rsa_not_elliptic_curves(tmp_path: Path) -> None:
    """IR 8547 deprecates 112-bit keys after 2030; RSA-2048 is 112 bits, P-256 is 128."""
    ec = _assess(
        tmp_path / "ec",
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "def key():\n"
        "    return ec.generate_private_key(ec.SECP256R1())\n",
    )
    rsa = _assess(
        tmp_path / "rsa",
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def key():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
    )
    state = lambda r, i: {m.id: m.state for m in r.milestones}[i]  # noqa: E731
    assert state(ec, "nist-sig-deprecated") == "clear"
    assert state(ec, "nist-sig-disallowed") == "due"
    assert state(rsa, "nist-sig-deprecated") == "due"


def test_md5_is_overdue_without_inventing_a_year(tmp_path: Path) -> None:
    readiness = _assess(
        tmp_path, "import hashlib\ndef h(b):\n    return hashlib.md5(b).hexdigest()\n"
    )
    md5 = {m.id: m for m in readiness.milestones}["nist-md5"]
    assert md5.state == "overdue" and md5.in_force and md5.year is None
    action = {a.id: a for a in readiness.actions}["replace_weak_now"]
    assert action.in_force and action.by is None
