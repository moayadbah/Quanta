"""Every finding that needs action gets an entry in Changes (round five).

A finding needs action when readiness classes it quantum-vulnerable, weak, or unconfirmed.
Each one ends in exactly one of three places:

* an automatic patch (``FixPlan.files``), where the change is safe;
* a refusal with its reason (``FixPlan.skipped``), where changing it would break a protocol,
  stored data or a test's fixed expected value;
* a guided migration (``FixPlan.guides``), where no automatic patch is safe: the target
  algorithm, real example code (``config/migrations.json``, executed by the tests) and the
  published rule behind it.

Nothing actionable is dropped: :func:`uncovered` is empty by construction, and a test
asserts it on real repositories.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from functools import lru_cache
from typing import Any

from quanta.core.fixes import FixPlan, Guide, GuideSite, Skipped
from quanta.resources import asset_path

ACTIONABLE = {"vulnerable", "weak", "review"}
WEAK_HASHES = {"MD5", "SHA1"}
LEGACY_CIPHERS = {"3DES", "DES", "RC4", "BLOWFISH", "MODE-ECB"}


@lru_cache(maxsize=1)
def migrations() -> dict[str, dict[str, Any]]:
    data = json.loads(asset_path("config/migrations.json").read_text(encoding="utf-8"))
    return {guide["id"]: guide for guide in data["guides"]}


def guide_for(finding: Mapping[str, Any]) -> str:
    """The migration that fits one finding that has no patch and no refusal."""
    readiness = finding.get("readiness") or {}
    exposure = set(readiness.get("exposure") or ())
    algorithms = set(finding.get("algorithms") or ()) | (
        {finding["algorithm"]} if finding.get("algorithm") else set()
    )
    if finding.get("form") == "implementation":
        return "implements-classical-primitive"
    if readiness.get("status") == "review" or readiness.get("assumed"):
        return "confirm-algorithm"
    if "tls" in exposure:
        return "tls-hybrid"
    if "key_exchange" in exposure:
        if "RSA" in algorithms:
            return "rsa-encryption-ml-kem"
        return "key-exchange-hybrid-ml-kem"
    if "signature" in exposure:
        return "signature-hybrid-ml-dsa"
    if "weak_cipher" in exposure or algorithms & LEGACY_CIPHERS:
        return "legacy-cipher-aes-gcm"
    return "weak-hash-manual"


def _key(path: str, line: int) -> tuple[str, int]:
    return path, line


def cover(plan: FixPlan, findings: Iterable[Mapping[str, Any]]) -> FixPlan:
    """Return ``plan`` with a refusal or a guide for every actionable finding it misses."""
    patched = {_key(f.path, c.line) for f in plan.files for c in f.changes}
    refused = {_key(s.path, s.line) for s in plan.skipped}
    skipped = list(plan.skipped)
    grouped: dict[str, list[GuideSite]] = {}
    for finding in findings:
        status = (finding.get("readiness") or {}).get("status")
        if status not in ACTIONABLE:
            continue
        key = _key(str(finding["file"]), int(finding["line"]))
        if key in patched or key in refused:
            continue
        algorithms = set(finding.get("algorithms") or ()) | (
            {finding["algorithm"]} if finding.get("algorithm") else set()
        )
        if finding.get("role") != "source" and algorithms & WEAK_HASHES:
            skipped.append(
                Skipped(
                    path=key[0],
                    line=key[1],
                    rule="weak-hash-to-sha256",
                    code="TEST_EXPECTATION",
                    detail=(
                        "Test and example code compares results against fixed expected "
                        "values computed with this hash. Update the expected values "
                        "deliberately, together with the code under test."
                    ),
                )
            )
            refused.add(key)
            continue
        guide = guide_for(finding)
        grouped.setdefault(guide, []).append(
            GuideSite(
                finding_id=str(finding["id"]),
                path=key[0],
                line=key[1],
                name=str(finding.get("name") or ""),
                algorithm=str(finding.get("algorithm") or ""),
                role=str(finding.get("role") or "source"),
            )
        )
    order = list(migrations())
    guides = [
        Guide(id=guide, sites=sorted(sites, key=lambda s: (s.path, s.line, s.name)))
        for guide, sites in sorted(grouped.items(), key=lambda item: order.index(item[0]))
    ]
    return plan.model_copy(update={"skipped": skipped, "guides": guides})


def uncovered(plan: FixPlan, findings: Iterable[Mapping[str, Any]]) -> list[tuple[str, int]]:
    """Actionable findings with no patch, refusal or guide. Empty after :func:`cover`."""
    covered = {_key(f.path, c.line) for f in plan.files for c in f.changes}
    covered |= {_key(s.path, s.line) for s in plan.skipped}
    covered |= {_key(s.path, s.line) for g in plan.guides for s in g.sites}
    return [
        _key(str(f["file"]), int(f["line"]))
        for f in findings
        if (f.get("readiness") or {}).get("status") in ACTIONABLE
        and _key(str(f["file"]), int(f["line"])) not in covered
    ]
