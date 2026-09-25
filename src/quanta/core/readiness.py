"""Post-quantum readiness against published standards (round four).

Every finding in shipped code is classified by what a quantum computer, or today's
cryptanalysis, does to it. The published milestones in ``config/standards.json`` (NIST,
NSA CNSA 2.0, NCA, the EU roadmap, UK NCSC, US EO 14412) are then applied to those classes.
Nothing here is Quanta's opinion: each milestone carries its source, and the output cites
the sites each one affects.

Conservative by design. An asymmetric call whose algorithm the parser cannot see is
assumed classical (quantum-vulnerable) and flagged for review: telling a team they are
safe when they are not is the worst error this module can make.

Deterministic: the reference year is the standards file's ``checked`` date, never the
clock, so the same commit gives byte-identical ``readiness.json``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from functools import lru_cache
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from quanta.core.models import CryptoSite
from quanta.core.ruleset_v2 import ALGORITHMS
from quanta.resources import asset_path

Exposure = Literal[
    "key_exchange", "tls", "signature", "sha1", "md5", "weak_cipher", "pq_hybrid", "pq_standalone"
]
Status = Literal["vulnerable", "weak", "pq", "safe", "review"]
Verdict = Literal["no_source", "no_crypto", "at_risk", "in_transition", "ready"]

KEX_ALGORITHMS = {"X25519", "X448", "DH", "ECDH"}
HYBRID = {"MLKEM768-X25519"}
WEAK_CIPHERS = {"3DES", "DES", "RC4", "BLOWFISH", "MODE-ECB"}
ASYMMETRIC = {"signature", "key_generation", "key_loading", "key_agreement", "certificate"}


class SiteReadiness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Status
    exposure: tuple[Exposure, ...] = ()
    assumed: bool = False


class MilestoneResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    framework: str
    source: str
    year: int | None
    rule: str
    sites: int
    state: Literal["clear", "due", "overdue", "met"]
    #: The rule already applies (MD5 was never approved; TDEA encryption ended in 2023).
    in_force: bool = False


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    priority: int
    by: int | None
    sites: int
    in_force: bool = False
    citations: tuple[str, ...]
    sources: tuple[str, ...]


class Readiness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: int = 1
    #: False when the time limit stopped reading before all shipped code was read.
    complete: bool = True
    source_unread: int = 0
    checked: str
    reference_year: int
    verdict: Verdict
    counts: dict[str, int]
    earliest_year: int | None
    earliest_milestone: str | None
    overdue: tuple[str, ...]
    milestones: tuple[MilestoneResult, ...]
    actions: tuple[Action, ...]
    frameworks: tuple[str, ...]


@lru_cache(maxsize=1)
def standards() -> dict[str, Any]:
    text = asset_path("config/standards.json").read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


def _algorithms(site: CryptoSite) -> set[str]:
    return set(site.algorithms or ((site.algorithm,) if site.algorithm else ()))


def classify(site: CryptoSite) -> SiteReadiness:
    """What quantum computing, or today's cryptanalysis, does to one site."""
    algorithms = set(site.algorithms or ((site.algorithm,) if site.algorithm else ()))
    infos = [ALGORITHMS[a] for a in algorithms if a in ALGORITHMS]
    exposure: list[Exposure] = []
    if algorithms & HYBRID:
        exposure.append("pq_hybrid")
    elif any(i.pq for i in infos) or site.category in {"pq_kem", "pq_signature"}:
        exposure.append("pq_standalone")
    if "MD5" in algorithms:
        exposure.append("md5")
    if "SHA1" in algorithms:
        exposure.append("sha1")
    if algorithms & WEAK_CIPHERS:
        exposure.append("weak_cipher")
    if site.category == "tls":
        exposure.append("tls")
    quantum = [a for a in algorithms if a in ALGORITHMS and ALGORITHMS[a].quantum_vulnerable]
    assumed = False
    if quantum:
        if site.category == "key_agreement" or set(quantum) <= KEX_ALGORITHMS:
            exposure.append("key_exchange")
        else:
            exposure.append("signature")
    elif site.category in ASYMMETRIC and not any(i.pq for i in infos) and not algorithms & HYBRID:
        # The parser could not see the algorithm of an asymmetric call: assume classical.
        exposure.append("key_exchange" if site.category == "key_agreement" else "signature")
        assumed = True

    if any(e in exposure for e in ("md5", "weak_cipher")):
        status: Status = "weak"
    elif any(e in exposure for e in ("key_exchange", "signature", "tls")):
        status = "review" if assumed else "vulnerable"
    elif "sha1" in exposure:
        status = "weak"
    elif any(e in exposure for e in ("pq_hybrid", "pq_standalone")):
        status = "pq"
    elif site.category == "token" and not algorithms:
        status = "review"
    else:
        status = "safe"
    return SiteReadiness(status=status, exposure=tuple(dict.fromkeys(exposure)), assumed=assumed)


#: A post-quantum algorithm and its classical partner in one module form one hybrid
#: construction (paramiko's mlkem768x25519-sha256 composes ML-KEM-768 and X25519 in
#: kex_mlkem.py). Per-site classification cannot see that; this pass can.
_HYBRID_PAIRS = (("pq_kem", "key_exchange"), ("pq_signature", "signature"))
_HYBRID = SiteReadiness(status="pq", exposure=("pq_hybrid",))


def classify_all(sites: Iterable[CryptoSite]) -> dict[str, SiteReadiness]:
    """Classify every site, then recognise hybrids composed within one file.

    Only a site whose sole exposure is the classical half (key exchange or signature, with
    the algorithm actually seen) is folded into a hybrid; a weak hash beside it is not.
    """
    items = [(s, classify(s)) for s in sites]
    result = {s.site_id: r for s, r in items}
    for pq_category, classical in _HYBRID_PAIRS:
        pq_files = {
            s.file for s, r in items if s.category == pq_category and "pq_standalone" in r.exposure
        }
        classical_files = {s.file for s, r in items if r.exposure == (classical,) and not r.assumed}
        for s, r in items:
            if s.file not in pq_files & classical_files:
                continue
            if (s.category == pq_category and "pq_standalone" in r.exposure) or (
                r.exposure == (classical,) and not r.assumed
            ):
                result[s.site_id] = _HYBRID
    return result


_APPLIES_EXPOSURE = {
    "key_exchange": {"key_exchange"},
    "tls": {"tls"},
    "signature": {"signature"},
    "sha1": {"sha1"},
    "md5": {"md5"},
    "weak_cipher": {"weak_cipher"},
    "pq_standalone": {"pq_standalone"},
}


def assess(
    sites: Iterable[CryptoSite],
    files_scanned: int | None = None,
    source_unread: int = 0,
) -> Readiness:
    """Readiness of shipped code (source role) against every milestone in the file."""
    data = standards()
    reference = int(str(data["checked"])[:4])
    shipped = [s for s in sites if s.kind == "crypto_call" and s.role == "source"]
    classes = classify_all(shipped)
    classified = [(s, classes[s.site_id]) for s in shipped]
    counts: dict[str, int] = dict.fromkeys(("vulnerable", "weak", "pq", "safe", "review"), 0)
    by_exposure: dict[str, list[CryptoSite]] = {}
    for site, result in classified:
        counts[result.status] += 1
        for e in result.exposure:
            by_exposure.setdefault(e, []).append(site)
        if result.assumed:
            by_exposure.setdefault("assumed", []).append(site)
    counts["sites"] = len(shipped)
    for e in ("key_exchange", "tls", "signature"):
        counts[e] = len(by_exposure.get(e, []))

    milestones: list[MilestoneResult] = []
    for m in data["milestones"]:
        applies = set(m["applies"])
        # A rule limited to some algorithms (NIST's 112-bit rows: RSA and finite-field DH)
        # still counts a site whose algorithm cannot be read, as the assessment assumes the worst.
        only = set(m.get("algorithms", ()))
        affected: set[str] = set()
        for exposure, exposure_names in _APPLIES_EXPOSURE.items():
            if applies & exposure_names:
                affected |= {
                    s.site_id
                    for s in by_exposure.get(exposure, [])
                    if not only or not _algorithms(s) or _algorithms(s) & only
                }
        year = m["year"]
        in_force = bool(m.get("in_force"))
        if "inventory" in applies:
            state = "met"  # this analysis is the inventory both milestones ask for
        elif not affected:
            state = "clear"
        elif in_force or (year is not None and year <= reference):
            state = "overdue"
        else:
            state = "due"
        milestones.append(
            MilestoneResult(
                id=m["id"],
                framework=m["framework"],
                source=m["source"],
                year=year,
                rule=m["rule"],
                sites=len(affected),
                state=state,
                in_force=in_force,
            )
        )
    due = [m for m in milestones if m.state == "due" and m.year is not None]
    earliest = min(due, key=lambda m: (m.year, m.id)) if due else None

    def cite(group: Iterable[CryptoSite]) -> tuple[str, ...]:
        return tuple(sorted({s.citation for s in group}))

    def first_year(ids: Iterable[str]) -> int | None:
        # Only milestones that touch these sites: RSA-only rules do not date an ECDSA action.
        years = [
            m.year
            for m in milestones
            if m.id in set(ids) and m.year is not None and m.state in {"due", "overdue"}
        ]
        return min(years) if years else None

    actions: list[Action] = []
    weak_now = by_exposure.get("md5", []) + by_exposure.get("weak_cipher", [])
    if weak_now:
        actions.append(
            Action(
                id="replace_weak_now",
                priority=1,
                by=None,
                in_force=True,
                sites=len({s.site_id for s in weak_now}),
                citations=cite(weak_now),
                sources=("nist-sp-800-131a-r2",),
            )
        )
    kex = by_exposure.get("key_exchange", []) + by_exposure.get("tls", [])
    if kex:
        actions.append(
            Action(
                id="hybrid_key_exchange",
                priority=2,
                by=first_year(["nist-kex-deprecated", "eu-high-risk", "us-kex"]),
                sites=len({s.site_id for s in kex}),
                citations=cite(kex),
                sources=(
                    ("nist-ir-8547", "eu-pqc-roadmap", "nca-ncs-2-2025", "openssl-3-5")
                    if by_exposure.get("tls")
                    else ("nist-ir-8547", "eu-pqc-roadmap", "nca-ncs-2-2025")
                ),
            )
        )
    sig = by_exposure.get("signature", [])
    if sig:
        actions.append(
            Action(
                id="pq_signatures",
                priority=3,
                by=first_year(["nist-sig-deprecated", "nsa-signing"]),
                sites=len({s.site_id for s in sig}),
                citations=cite(sig),
                sources=("nist-ir-8547", "nsa-cnsa-2", "uk-ncsc-pqc"),
            )
        )
    sha1 = by_exposure.get("sha1", [])
    if sha1:
        actions.append(
            Action(
                id="retire_sha1",
                priority=4,
                by=first_year(["nist-sha1"]),
                sites=len(sha1),
                citations=cite(sha1),
                sources=("nist-sha1-retirement", "nist-sp-800-131a-r2"),
            )
        )
    standalone = by_exposure.get("pq_standalone", [])
    if standalone:
        actions.append(
            Action(
                id="make_hybrid",
                priority=5,
                by=None,
                sites=len(standalone),
                citations=cite(standalone),
                sources=("nca-ncs-2-2025",),
            )
        )
    assumed = by_exposure.get("assumed", [])
    if assumed:
        actions.append(
            Action(
                id="confirm_algorithms",
                priority=6,
                by=None,
                sites=len(assumed),
                citations=cite(assumed),
                sources=("nist-ir-8547",),
            )
        )

    if files_scanned == 0:
        # Nothing was read (no Python source): "no cryptography" would be a false comfort.
        verdict: Verdict = "no_source"
    elif not shipped:
        verdict = "no_crypto"
    elif counts["vulnerable"] + counts["weak"] + counts["review"] == 0:
        verdict = "ready"
    elif counts["pq"]:
        verdict = "in_transition"
    else:
        verdict = "at_risk"
    return Readiness(
        complete=source_unread == 0,
        source_unread=source_unread,
        checked=str(data["checked"]),
        reference_year=reference,
        verdict=verdict,
        counts=counts,
        earliest_year=earliest.year if earliest else None,
        earliest_milestone=earliest.id if earliest else None,
        overdue=tuple(m.id for m in milestones if m.state == "overdue"),
        milestones=tuple(milestones),
        actions=tuple(actions),
        frameworks=tuple(f["id"] for f in data["frameworks"]),
    )
