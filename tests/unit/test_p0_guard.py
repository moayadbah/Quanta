"""P0 refusal guards (Master Plan 9.2; evidence/PROTOCOL-R3.md K1).

In round two P0 regressed both real projects it touched. These fixtures reproduce the two
shapes: a hash chosen by the peer (HTTP Digest) and a hash stored as a signing default.
"""

from __future__ import annotations

from quanta.core.fixes import propose_with_skips


def test_protocol_negotiated_hash_is_refused() -> None:
    source = (
        "import hashlib\n\n"
        "def build(alg):\n"
        '    if alg == "MD5":\n'
        "        def h(x):\n"
        "            return hashlib.md5(x).hexdigest()\n"
        "        return h\n"
    )
    proposal, skipped = propose_with_skips(source, "auth.py")
    assert proposal is None
    assert [s.code for s in skipped] == ["PROTOCOL_NEGOTIATED"]
    assert skipped[0].line == 6


def test_stored_default_digest_is_refused() -> None:
    """The itsdangerous shape: a function returning SHA-1, stored as a class default."""
    source = (
        "import hashlib\n\n"
        'def _lazy_sha1(string=b""):\n'
        "    return hashlib.sha1(string)\n\n"
        "class HMACAlgorithm:\n"
        "    default_digest_method = staticmethod(_lazy_sha1)\n"
    )
    proposal, skipped = propose_with_skips(source, "signer.py")
    assert proposal is None
    assert [s.code for s in skipped] == ["STORED_FORMAT_DEFAULT"]


def test_default_argument_is_refused() -> None:
    source = "import hashlib\n\ndef sign(data, digest=hashlib.md5()):\n    return digest\n"
    proposal, skipped = propose_with_skips(source, "a.py")
    assert proposal is None
    assert [s.code for s in skipped] == ["STORED_FORMAT_DEFAULT"]


def test_plain_fingerprint_is_still_proposed() -> None:
    source = "import hashlib\n\ndef fingerprint(b):\n    return hashlib.md5(b).hexdigest()\n"
    proposal, skipped = propose_with_skips(source, "a.py")
    assert proposal is not None
    assert [c.after for c in proposal.changes] == ["sha256"]
    assert skipped == []


def test_usedforsecurity_false_is_left_alone() -> None:
    source = "import hashlib\nhashlib.md5(b'', usedforsecurity=False)\n"
    proposal, skipped = propose_with_skips(source, "a.py")
    assert proposal is None
    assert skipped == []


def test_public_plan_states_it_is_unverified() -> None:
    from quanta.core.fixes import FixPlan

    public = FixPlan().public()
    assert public["verified"] is False
    assert "Not verified" in public["validation"]
