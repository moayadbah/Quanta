# ADR-019 — X-Wing combiner follows draft-10, not §3.9's byte order

**Status:** Accepted
**Date:** 2026-08-08
**Corrects §3.9 of the Technical Documentation. Upholds ADR-004.**

## Context

§3.9 specifies the X-Wing combiner as:

```
SHA3-256(XWingLabel ‖ ss_M ‖ ss_X ‖ ct_X ‖ pk_X)          # label FIRST
```

`draft-connolly-cfrg-xwing-kem-10` §5.3 defines it as:

```
def Combiner(ss_M, ss_X, ct_X, pk_X):
  return SHA3-256(concat(ss_M, ss_X, ct_X, pk_X, XWingLabel))   # label LAST
```

The document's order is wrong. The label is a domain separator appended at the end, not
prepended.

This is not cosmetic. ADR-004's entire justification for X-Wing over naive concatenation is
that X-Wing is *published and security-proven* (Barbosa et al., IACR CiC 1(1), 2024). A
combiner with permuted inputs is a **different construction** to which that proof does not
apply — it would be exactly the hand-rolled combiner ADR-004 exists to avoid, while claiming
otherwise in the thesis. Since Quanta generates both sides of the round-trip property, the
error would never surface as a test failure; it would surface as an unsupportable claim.

Two further corrections to §3.9 and §5.3.4, verified against `cryptography` 48.0.1:

- **`encapsulate()` returns `(shared_secret, ciphertext)`**, not `(ct, ss)` as §5.3.4 writes.
- **X-Wing's decapsulation key is a 32-byte seed** expanded with SHAKE-256 to 96 bytes:
  bytes `0:64` seed ML-KEM-768 KeyGen, bytes `64:96` are the X25519 scalar. §3.9's
  "32-byte expandable seed" is correct for X-Wing; note that `cryptography`'s own
  `MLKEM768PrivateKey.from_seed_bytes` separately takes a **64**-byte seed, which is exactly
  the `expanded[0:64]` slice.

## Decision

Implement `shim/_quanta_hybrid.py` to the draft, not the document:

```python
combined = sha3_256(ss_M + ss_X + ct_X + pk_X + XWingLabel)
XWingLabel = b"\./" + b"/^\\"     # 6 bytes, hex 5c2e2f2f5e5c
```

Sizes asserted by the Hypothesis property (DoD-V2): ciphertext 1120 = 1088 + 32,
public key 1216 = 1184 + 32, shared secret 32.

## Verification

This decision is not argued from reading alone. draft-10 Appendix C publishes three test
vectors, and decapsulation requires no randomness — so it is fully reproducible from
published data. Both orders were run against vector 0:

```
draft-10 order (label last)   matches published ss:  True
doc §3.9 order (label first)  matches published ss:  False
```

All three vectors match on **both** the derived 1216-byte encapsulation key and the
32-byte shared secret. The vectors are committed at
`tests/fixtures/xwing_draft10_vectors.json` and asserted by
`tests/unit/test_shim_xwing.py::test_kat_decapsulation`, with
`test_documentation_section_3_9_combiner_order_is_rejected` guarding against someone
later "correcting" the code back to the document.

Note the round-trip property alone could never have caught this: Quanta generates both
sides, so a permuted combiner round-trips perfectly. Only the external KAT distinguishes
X-Wing from a lookalike.

## Consequences

- The shim is genuinely X-Wing, so ADR-004's security argument holds as written.
- §3.9 of the Technical Documentation should be corrected in the next revision; until then
  this ADR is the authority and the code cites it.
- X-Wing remains an IETF draft, not an RFC (RR-5). Unchanged by this decision.

## Revisit trigger

X-Wing reaches RFC status with a changed combiner, or the draft revision advances past 10
with a normative change to `Combiner`.
