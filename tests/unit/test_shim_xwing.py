"""DoD-V2 — the X-Wing shim.

Three layers of assurance, in increasing order of strength:

1. **Sizes and shapes.** Cheap, catches wiring mistakes.
2. **A Hypothesis round-trip property** over >= 1000 examples, as DoD-V2 requires.
3. **Known-answer tests against ``draft-connolly-cfrg-xwing-kem-10`` Appendix C.**

Layer 3 is the one that matters, and it is why this file exists in this shape. The
round-trip property is *self-consistent*: it would pass just as happily against a
combiner whose inputs were permuted, because Quanta generates both sides. Only a KAT
against externally published vectors can show that this module implements X-Wing rather
than a lookalike — which is exactly the claim ADR-004 rests on. See ADR-019.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from quanta.shim import _quanta_hybrid as xwing

_VECTORS_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "xwing_draft10_vectors.json"


def _load_vectors() -> list[dict[str, str]]:
    with _VECTORS_PATH.open() as fh:
        data: list[dict[str, str]] = json.load(fh)
    return data


VECTORS = _load_vectors()


# --------------------------------------------------------------------------------------
# Layer 1 — sizes and constants
# --------------------------------------------------------------------------------------


def test_label_is_the_draft_domain_separator() -> None:
    """draft-10 §5.3: a 6-byte ASCII label, hex 5c2e2f2f5e5c."""
    assert xwing._XWING_LABEL == b"\\./" + b"/^\\"
    assert len(xwing._XWING_LABEL) == 6
    assert xwing._XWING_LABEL.hex() == "5c2e2f2f5e5c"


def test_declared_sizes_match_the_draft() -> None:
    assert xwing.XWING_SK_SIZE == 32
    assert xwing.XWING_PK_SIZE == 1216  # 1184 ML-KEM-768 + 32 X25519
    assert xwing.XWING_CT_SIZE == 1120  # 1088 ML-KEM-768 + 32 X25519
    assert xwing.XWING_SS_SIZE == 32


def test_generated_keypair_has_the_declared_sizes() -> None:
    sk, pk = xwing.generate_keypair()
    assert len(sk) == xwing.XWING_SK_SIZE
    assert len(pk) == xwing.XWING_PK_SIZE


def test_ciphertext_is_1120_bytes() -> None:
    """DoD-V2 names this length explicitly."""
    _sk, pk = xwing.generate_keypair()
    ct, ss = xwing.encapsulate(pk)
    assert len(ct) == 1120
    assert len(ss) == 32


@pytest.mark.parametrize(
    ("bad_len", "func"),
    [
        (1215, "encapsulate"),
        (1217, "encapsulate"),
    ],
)
def test_encapsulate_rejects_wrong_public_key_length(bad_len: int, func: str) -> None:
    with pytest.raises(ValueError, match="public key must be"):
        xwing.encapsulate(b"\x00" * bad_len)


def test_decapsulate_rejects_wrong_ciphertext_length() -> None:
    sk, _pk = xwing.generate_keypair()
    with pytest.raises(ValueError, match="ciphertext must be"):
        xwing.decapsulate(sk, b"\x00" * 1119)


def test_seed_must_be_32_bytes() -> None:
    with pytest.raises(ValueError, match="seed must be"):
        xwing.generate_keypair(b"\x00" * 31)


# --------------------------------------------------------------------------------------
# Layer 2 — the DoD-V2 round-trip property
# --------------------------------------------------------------------------------------


@settings(
    max_examples=1000,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(seed=st.binary(min_size=32, max_size=32))
def test_roundtrip_property(seed: bytes) -> None:
    """DoD-V2: ``decapsulate(sk, ct) == ss`` for ``(ct, ss) = encapsulate(pk)``.

    Hypothesis drives key generation; encapsulation draws its own randomness, so each
    example exercises a fresh ML-KEM ciphertext and a fresh X25519 ephemeral.
    """
    sk, pk = xwing.generate_keypair(seed)
    ct, ss = xwing.encapsulate(pk)

    assert len(ct) == xwing.XWING_CT_SIZE
    assert len(ss) == xwing.XWING_SS_SIZE
    assert xwing.decapsulate(sk, ct) == ss


@settings(max_examples=50, deadline=None)
@given(seed=st.binary(min_size=32, max_size=32))
def test_keypair_generation_is_deterministic_in_the_seed(seed: bytes) -> None:
    assert xwing.generate_keypair(seed) == xwing.generate_keypair(seed)


def test_wrong_key_yields_a_different_secret_rather_than_an_error() -> None:
    """ML-KEM decapsulation is implicitly rejecting: a bad key gives a wrong secret."""
    _sk_a, pk_a = xwing.generate_keypair()
    sk_b, _pk_b = xwing.generate_keypair()
    ct, ss = xwing.encapsulate(pk_a)
    assert xwing.decapsulate(sk_b, ct) != ss


# --------------------------------------------------------------------------------------
# Layer 3 — known-answer tests against the published draft
# --------------------------------------------------------------------------------------


def test_vectors_are_present_and_well_formed() -> None:
    assert len(VECTORS) >= 3
    for v in VECTORS:
        assert len(bytes.fromhex(v["seed"])) == 32
        assert len(bytes.fromhex(v["pk"])) == 1216
        assert len(bytes.fromhex(v["ct"])) == 1120
        assert len(bytes.fromhex(v["ss"])) == 32


@pytest.mark.parametrize("idx", range(len(VECTORS)))
def test_kat_public_key_derivation(idx: int) -> None:
    """The 32-byte seed must expand to exactly the draft's encapsulation key.

    Covers SHAKE-256 expansion, the ML-KEM-768 seed split, and X25519 scalar derivation.
    """
    v = VECTORS[idx]
    _sk, pk = xwing.generate_keypair(bytes.fromhex(v["seed"]))
    assert pk.hex() == v["pk"]


@pytest.mark.parametrize("idx", range(len(VECTORS)))
def test_kat_decapsulation(idx: int) -> None:
    """Decapsulating the draft's ciphertext must yield the draft's shared secret.

    This is the load-bearing assertion for ADR-019. Decapsulation needs no randomness, so
    it is fully reproducible from published data — and it pins the combiner's byte order,
    which no self-generated round-trip could.
    """
    v = VECTORS[idx]
    ss = xwing.decapsulate(bytes.fromhex(v["sk"]), bytes.fromhex(v["ct"]))
    assert ss.hex() == v["ss"]


def test_documentation_section_3_9_combiner_order_is_rejected() -> None:
    """Regression guard for ADR-019.

    Technical Documentation §3.9 places ``XWingLabel`` first. draft-10 §5.3 places it
    last. If someone "fixes" the combiner to match the document, the KAT above breaks —
    this test states *why*, so the failure is diagnosed in seconds rather than debugged
    as an ML-KEM problem.
    """
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    v = VECTORS[0]
    seed, ct = bytes.fromhex(v["seed"]), bytes.fromhex(v["ct"])
    sk_m, sk_x, pk_x = xwing._expand_decapsulation_key(seed)
    ct_m, ct_x = ct[:1088], ct[1088:]
    ss_m = sk_m.decapsulate(ct_m)
    ss_x = sk_x.exchange(X25519PublicKey.from_public_bytes(ct_x))
    label = xwing._XWING_LABEL

    draft_order = hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + label).digest()
    doc_order = hashlib.sha3_256(label + ss_m + ss_x + ct_x + pk_x).digest()

    assert draft_order.hex() == v["ss"], "draft-10 order must match the published vector"
    assert doc_order.hex() != v["ss"], "§3.9 order must NOT match — that is the bug"


# --------------------------------------------------------------------------------------
# ADR-003 — liboqs is forbidden in anything Quanta emits or vendors
# --------------------------------------------------------------------------------------


def test_shim_does_not_import_oqs() -> None:
    source = Path(xwing.__file__).read_text()
    assert "import oqs" not in source
    assert "from oqs" not in source
