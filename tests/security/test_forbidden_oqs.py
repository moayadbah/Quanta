"""§9.4 / DoD-E4 — liboqs is never imported, and never emitted.

liboqs' own README states it "is designed for prototyping and evaluating quantum-resistant
cryptography" and that algorithm security "may rapidly change… and may ultimately be
completely insecure". A tool that inserts a self-declared prototype library into other
people's repositories produces rejected pull requests and a damaged reputation (ADR-003).

Two distinct claims are tested, and the distinction matters:

* Quanta **detects** ``oqs.KeyEncapsulation`` — the string appears in the crypto ruleset
  because finding it in a target repository is a legitimate result.
* Quanta never **imports** it and never **emits** it into a patch.

So this file matches on import *statements* via ``ast``, not on substrings. A grep-based
check would fail on ``core/rules.py`` and would tempt someone to weaken it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "quanta"
SHIM = SRC / "shim" / "_quanta_hybrid.py"


def _python_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def _imports_oqs(tree: ast.Module) -> list[int]:
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            hits += [node.lineno for a in node.names if a.name.split(".")[0] == "oqs"]
        elif (
            isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] == "oqs"
        ):
            hits.append(node.lineno)
    return hits


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: p.name)
def test_no_module_imports_oqs(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    assert not _imports_oqs(tree), f"{path.name} imports oqs — prohibited by ADR-003"


def test_the_vendored_shim_is_textually_clean() -> None:
    """The shim is copied verbatim into target repositories, so check its text directly."""
    source = SHIM.read_text(encoding="utf-8")
    for line in source.splitlines():
        stripped = line.strip()
        assert not stripped.startswith("import oqs")
        assert not stripped.startswith("from oqs")


def test_ruleset_still_detects_oqs() -> None:
    """The prohibition is on emitting oqs, not on finding it. Guard against over-fixing."""
    from quanta.core.rules import CRYPTO_QUALIFIED_NAMES

    assert "oqs.KeyEncapsulation" in CRYPTO_QUALIFIED_NAMES
    assert "oqs.Signature" in CRYPTO_QUALIFIED_NAMES


def test_patch_scanner_flags_an_oqs_diff() -> None:
    """DoD-E4 gate, ready before the engines that will need it.

    Engines land in build order step 8; this asserts the check they must pass already
    works, so it cannot be quietly skipped later.
    """
    from quanta.core.rules import patch_contains_forbidden_import

    hostile = "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,3 @@\n import os\n+import oqs\n x = 1\n"
    clean = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,2 +1,3 @@\n"
        " import os\n"
        "+from _quanta_hybrid import encapsulate\n"
        " x = 1\n"
    )
    removal = "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,1 @@\n-import oqs\n x = 1\n"

    assert patch_contains_forbidden_import(hostile) is True
    assert patch_contains_forbidden_import(clean) is False
    # Removing an oqs import is exactly what a good migration does — never flag it.
    assert patch_contains_forbidden_import(removal) is False
