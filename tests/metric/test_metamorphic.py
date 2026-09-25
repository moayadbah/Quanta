"""Metamorphic relations of metric-v2 (Master Plan 8.9, MR1 to MR10).

Each test changes a small repository in a way whose effect on the score is known in
advance, and checks the direction of the change rather than a pinned number.
"""

from __future__ import annotations

from pathlib import Path

from quanta.core.analyze import write_artifacts
from quanta.core.models import ScoreReport

from .helpers import BASE, analyse


def _score(tmp_path: Path, files: dict[str, str], name: str = "repo") -> ScoreReport:
    outcome = analyse(tmp_path / name, files)
    assert outcome.score.status == "scored", outcome.score.refusal
    return outcome.score


def test_base_is_scored(tmp_path: Path) -> None:
    score = _score(tmp_path, BASE)
    assert score.coverage.touchpoints == 3
    assert score.factors["isolation_layer"].inputs["crypto_modules"] == 3


def test_mr1_a_module_without_crypto_does_not_lower_the_score(tmp_path: Path) -> None:
    base = _score(tmp_path, BASE, "base")
    grown = _score(tmp_path, {**BASE, "app/extra.py": "VALUE = 1\n"}, "grown")
    assert grown.agility_score >= base.agility_score  # type: ignore[operator]


def test_mr2_moving_the_calls_into_one_module_raises_the_score_by_15(tmp_path: Path) -> None:
    base = _score(tmp_path, BASE, "base")
    facade = {
        **BASE,
        "app/crypto.py": (
            "import hashlib\n\n\ndef sha256_hex(data: bytes) -> str:\n"
            "    return hashlib.sha256(data).hexdigest()\n\n\n"
            "def sha256_hex_b(data: bytes) -> str:\n"
            "    return hashlib.sha256(data).hexdigest()\n\n\n"
            "def sha256_hex_c(data: bytes) -> str:\n"
            "    return hashlib.sha256(data).hexdigest()\n"
        ),
        "app/users.py": (
            "from app import crypto\n\n\ndef fingerprint(data: bytes) -> str:\n"
            "    return crypto.sha256_hex(data)\n"
        ),
        "app/files.py": (
            "from app import crypto\n\n\ndef checksum(data: bytes) -> str:\n"
            "    return crypto.sha256_hex_b(data)\n"
        ),
        "app/tokens.py": (
            "from app import crypto\n\n\ndef token_id(data: bytes) -> str:\n"
            "    return crypto.sha256_hex_c(data)\n"
        ),
    }
    after = _score(tmp_path, facade, "facade")
    assert after.factors["isolation_layer"].normalised == 1.0
    assert after.agility_score - base.agility_score >= 15.0  # type: ignore[operator]


def test_mr3_configuring_one_call_raises_f_config(tmp_path: Path) -> None:
    base = _score(tmp_path, BASE, "base")
    configured = {
        **BASE,
        "app/users.py": (
            "import hashlib\nimport os\n\n\ndef fingerprint(data: bytes) -> str:\n"
            '    return hashlib.new(os.environ.get("D", "sha256"), data).hexdigest()\n'
        ),
    }
    after = _score(tmp_path, configured, "configured")
    assert (
        after.factors["selection_source"].normalised > base.factors["selection_source"].normalised
    )
    assert after.agility_score >= base.agility_score  # type: ignore[operator]


def test_mr4_test_code_changes_nothing_but_the_inventory(tmp_path: Path) -> None:
    base = _score(tmp_path, BASE, "base")
    tests = "import hashlib\n\n\ndef test_x() -> None:\n" + "".join(
        f"    hashlib.md5(b'{i}')\n" for i in range(10)
    )
    after = _score(tmp_path, {**BASE, "tests/test_x.py": tests}, "tests")
    assert after.agility_score == base.agility_score
    assert after.factors == base.factors
    assert after.coverage.sites_by_role["test"] == 10


def test_mr5_docs_and_examples_do_not_change_the_score(tmp_path: Path) -> None:
    base = _score(tmp_path, BASE, "base")
    copies = {**BASE}
    for prefix in ("docs/", "examples/"):
        copies.update({prefix + k: v for k, v in BASE.items()})
    after = _score(tmp_path, copies, "copies")
    assert after.agility_score == base.agility_score


def test_mr6_renaming_modules_consistently_does_not_change_the_score(tmp_path: Path) -> None:
    base = _score(tmp_path, BASE, "base")
    renamed = {
        k.replace("app/", "core/"): v.replace("from app ", "from core ") for k, v in BASE.items()
    }
    after = _score(tmp_path, renamed, "renamed")
    assert after.agility_score == base.agility_score


def test_mr7_reordering_functions_does_not_change_the_score(tmp_path: Path) -> None:
    base = _score(tmp_path, BASE, "base")
    reordered = {
        **BASE,
        "app/views.py": (
            "def other() -> int:\n    return 1\n\n\n"
            "def render(value: str) -> str:\n    return value.upper()\n"
        ),
    }
    after = _score(tmp_path, reordered, "reordered")
    assert after.factors["call_sites"] == base.factors["call_sites"]
    assert after.factors["isolation_layer"] == base.factors["isolation_layer"]
    assert after.factors["selection_source"] == base.factors["selection_source"]


def test_mr8_a_new_weak_hash_module_does_not_raise_the_score(tmp_path: Path) -> None:
    base = _score(tmp_path, BASE, "base")
    after = _score(
        tmp_path, {**BASE, "app/legacy.py": "import hashlib\n\nX = hashlib.md5(b'')\n"}, "legacy"
    )
    assert after.agility_score <= base.agility_score  # type: ignore[operator]


def test_mr9_two_runs_are_byte_identical(tmp_path: Path) -> None:
    outputs = []
    for run in ("one", "two"):
        outcome = analyse(tmp_path / run, BASE)
        out = tmp_path / f"out-{run}"
        write_artifacts(outcome, out)
        outputs.append(
            {n: (out / n).read_bytes() for n in ("cdg.json", "score.json", "fixes.json")}
        )
    assert outputs[0] == outputs[1]
    for data in outputs[0].values():
        assert b"\r" not in data and b"\\\\" not in data


def test_mr10_a_reference_site_replaces_a_call_site(tmp_path: Path) -> None:
    base = _score(tmp_path, BASE, "base")
    referenced = {
        **BASE,
        "app/users.py": (
            "import hashlib\n\nDIGEST = hashlib.sha256\n\n\n"
            "def fingerprint(data: bytes) -> str:\n    return DIGEST(data).hexdigest()\n"
        ),
    }
    after = _score(tmp_path, referenced, "referenced")
    assert after.coverage.touchpoints == base.coverage.touchpoints
