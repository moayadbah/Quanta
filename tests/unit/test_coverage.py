"""Round five: every finding that needs action has an entry in Changes.

python-ecdsa gave 88 findings and 5 changes. Now each quantum-vulnerable, weak or
unconfirmed finding ends as a patch, a refusal with its reason, or a guided migration
with real example code.
"""

from __future__ import annotations

from pathlib import Path

from quanta.core.analyze import analyze_path
from quanta.core.coverage import guide_for, migrations, uncovered
from quanta.core.models import Provenance
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


def _provenance() -> Provenance:
    return Provenance(
        repo="owner/name",
        commit_sha="a" * 40,
        analyzer_version=analyzer_version(),
        crypto_ruleset_version=CRYPTO_RULESET_VERSION,
    )


def test_nothing_actionable_is_left_without_an_entry() -> None:
    for name in ("hardcoded_crypto", "configured_crypto", "facade_crypto", "scattered_crypto"):
        outcome = analyze_path(FIXTURES / name, _provenance())
        assert uncovered(outcome.fixes, outcome.findings) == [], name


def test_quantum_vulnerable_findings_point_to_a_post_quantum_replacement() -> None:
    outcome = analyze_path(FIXTURES / "hardcoded_crypto", _provenance())
    vulnerable = [f for f in outcome.findings if f["readiness"]["status"] == "vulnerable"]
    assert vulnerable
    guided = {s.finding_id: g.id for g in outcome.fixes.guides for s in g.sites}
    for finding in vulnerable:
        assert guided.get(str(finding["id"])) in {
            "key-exchange-hybrid-ml-kem",
            "signature-hybrid-ml-dsa",
            "tls-hybrid",
            "rsa-encryption-ml-kem",
            "implements-classical-primitive",
        }


def test_guides_are_chosen_by_exposure() -> None:
    def finding(**kw: object) -> dict[str, object]:
        base: dict[str, object] = {"form": "call", "algorithms": [], "algorithm": None}
        base.update(kw)
        return base

    assert (
        guide_for(finding(readiness={"status": "vulnerable", "exposure": ["tls"]})) == "tls-hybrid"
    )
    assert (
        guide_for(
            finding(
                algorithm="RSA", readiness={"status": "vulnerable", "exposure": ["key_exchange"]}
            )
        )
        == "rsa-encryption-ml-kem"
    )
    assert (
        guide_for(
            finding(
                form="implementation", readiness={"status": "vulnerable", "exposure": ["signature"]}
            )
        )
        == "implements-classical-primitive"
    )
    assert guide_for(
        finding(readiness={"status": "review", "exposure": ["signature"], "assumed": True})
    ) == ("confirm-algorithm")
    assert set(migrations()) >= {
        "signature-hybrid-ml-dsa",
        "key-exchange-hybrid-ml-kem",
        "weak-hash-manual",
    }


def test_public_plan_carries_the_example_and_sources() -> None:
    outcome = analyze_path(FIXTURES / "hardcoded_crypto", _provenance())
    public = outcome.fixes.public()
    assert public["guides"]
    for guide in public["guides"]:
        assert guide["example"] and guide["sources"] and guide["sites"]
