from __future__ import annotations

import ast

import pytest

from quanta.core.fixes import FixPlan, propose, review
from quanta.errors import Reject


def plan(source: str) -> FixPlan:
    file = propose(source, "src/hashes.py")
    return FixPlan(files=[file] if file else [])


def test_aliases_shadowing_strings_and_nonsecurity_calls() -> None:
    result = plan("""import hashlib as h
from hashlib import md5 as legacy
text = "hashlib.md5(x)"
a = h.sha1(b"x")
b = legacy(b"x")
c = h.md5(b"x", usedforsecurity=False)
def shadow(legacy):
    return legacy(b"x")
""")
    assert len(result.files[0].changes) == 2
    selected = [c.id for c in result.files[0].changes]
    patched = review(result, selected)["files"][0]["content"]
    assert 'text = "hashlib.md5(x)"' in patched
    assert 'return legacy(b"x")' in patched
    assert 'h.md5(b"x", usedforsecurity=False)' in patched
    assert 'h.sha256(b"x")' in patched
    ast.parse(patched)


def test_selection_only_applies_selected_call_and_keeps_comments_and_crlf() -> None:
    result = plan('import hashlib\r\na = hashlib.md5(b"x")  # keep\r\nb = hashlib.sha1(b"x")\r\n')
    output = review(result, [result.files[0].changes[0].id])["files"][0]["content"]
    assert 'hashlib.sha256(b"x")  # keep\r\n' in output
    assert 'hashlib.sha1(b"x")\r\n' in output
    assert output.count("\r\n") == 3


def test_direct_imports_from_two_libraries_do_not_collide() -> None:
    result = plan("""from hashlib import sha1
from cryptography.hazmat.primitives.hashes import SHA1
x = sha1(b"x")
y = SHA1()
""")
    output = review(result, [c.id for c in result.files[0].changes])["files"][0]["content"]
    assert "sha256 as _quanta_sha256_sha256" in output
    assert "SHA256 as _quanta_sha256_SHA256" in output
    assert 'x = _quanta_sha256_sha256(b"x")' in output
    assert "y = _quanta_sha256_SHA256()" in output


@pytest.mark.parametrize(
    "path", ["../evil.py", "/tmp/evil.py", ".github/tool.py", "a/../b.py", "a\\b.py", "x\n.py"]
)
def test_proposals_never_modify_unsafe_paths(path: str) -> None:
    assert propose("import hashlib\nx=hashlib.md5(b'x')", path) is None


@pytest.mark.parametrize("selected", [[], ["unknown"], ["duplicate", "duplicate"]])
def test_review_rejects_unknown_empty_and_duplicate_selections(selected: list[str]) -> None:
    with pytest.raises(Reject, match="FIX_UNAVAILABLE"):
        review(plan("import hashlib\nx=hashlib.md5(b'x')"), selected)


def test_literal_constructor_and_deterministic_review_digest() -> None:
    result = plan('import hashlib\nx=hashlib.new("sha-1", b"x")\ny=hashlib.new(name="md5")')
    selected = [c.id for c in result.files[0].changes]
    first = review(result, selected)
    assert first["digest"] == review(result, list(reversed(selected)))["digest"]
    assert first["digest"] != review(result, selected[:1])["digest"]
    assert first["files"][0]["content"].count('"sha256"') == 2


def test_tampered_source_is_rejected() -> None:
    result = plan("import hashlib\nx=hashlib.md5(b'x')")
    changed = result.files[0].model_copy(update={"source": "# tampered"})
    with pytest.raises(Reject, match="REVIEW_STALE"):
        review(FixPlan(files=[changed]), [changed.changes[0].id])
