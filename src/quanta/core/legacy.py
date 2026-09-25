"""Runs written by an older engine, read with today's rules and never read as clean.

The live service can hold scans made by an earlier engine (analyzer 0.3.0 wrote no
``findings.json`` and no ``readiness.json``, knew nothing of file roles, and proposed patches
the current rules refuse). Reading those artifacts as if they were current turned missing
fields into zeros, and zeros into false reassurance: "no finding needs action" for an ECDSA
library. This module is the one place that decides what an older run can still say:

* its cryptographic calls are rebuilt from ``cdg.json`` and classed with today's rules;
* file roles come from the path, which is all the current engine uses too;
* its patches are proposed again from the source it retained (``fixes.reevaluate``);
* readiness is **not** invented: an assessment the engine did not make stays unmeasured, and
  every reader (report, PDF, workspace) says so and offers a rescan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from quanta.core.coverage import cover
from quanta.core.fixes import FixPlan, reevaluate
from quanta.core.readiness import classify
from quanta.core.roles import classify_role
from quanta.version import analyzer_version


@dataclass
class RunData:
    """What a report may state about one run, and what it must not."""

    findings: list[dict[str, Any]]
    plan: FixPlan
    readiness: dict[str, Any] | None
    #: Readiness, deadlines and verdict were measured by the engine that made the run.
    assessed: bool
    #: Every finding carries a file role (shipped code versus tests and docs).
    roles_measured: bool
    #: The engine version that produced the run, when it differs from this one.
    older_engine: str = ""
    #: Where the findings came from: the run's findings.json, or rebuilt from cdg.json.
    findings_source: str = "findings"
    notes: list[str] = field(default_factory=list)


def engine_of(score: dict[str, Any]) -> str:
    return str((score.get("provenance") or {}).get("analyzer_version", ""))


def _base(version: str) -> str:
    return version.split("+", 1)[0]


def _classed(finding: dict[str, Any]) -> dict[str, Any]:
    """Fill a role and a readiness class the older engine did not record."""
    out = dict(finding)
    out["file"] = str(out.get("file", "")).replace("\\", "/")
    if not out.get("role"):
        out["role"] = classify_role(out["file"])
    if not out.get("readiness"):
        algorithm = out.get("algorithm")
        algorithms = list(out.get("algorithms") or ([algorithm] if algorithm else []))
        if algorithms:
            site = SimpleNamespace(
                algorithms=algorithms,
                algorithm=algorithm,
                category=str(out.get("category") or ""),
                kind=str(out.get("kind") or "crypto_call"),
            )
            out["readiness"] = classify(site).model_dump()  # type: ignore[arg-type]
        else:
            # The algorithm was not recorded: never let "unknown" read as "no action".
            out["readiness"] = {"status": "review", "exposure": [], "assumed": True}
    return out


def findings_from_cdg(cdg: dict[str, Any]) -> list[dict[str, Any]]:
    """The cryptographic calls an older engine recorded in its graph."""
    out = []
    for node in cdg.get("nodes", []):
        if node.get("kind") != "crypto_call":
            continue
        out.append(
            {
                "id": str(node.get("id", "")),
                "kind": "crypto_call",
                "file": str(node.get("file", "")).replace("\\", "/"),
                "line": int(node.get("line") or 0),
                "name": str(node.get("qualified_name") or ""),
                "algorithm": node.get("algorithm"),
                "algorithms": [node["algorithm"]] if node.get("algorithm") else [],
            }
        )
    return sorted(out, key=lambda f: (f["file"], f["line"], f["name"]))


def normalise(
    *,
    score: dict[str, Any],
    readiness: dict[str, Any] | None,
    findings: list[dict[str, Any]] | None,
    plan: FixPlan,
    cdg: dict[str, Any] | None = None,
) -> RunData:
    """One run, read with today's rules, with every unmeasured fact marked as such."""
    source = "findings"
    if findings is None:
        findings = findings_from_cdg(cdg or {})
        source = "cdg"
    roles_measured = bool(findings) and all(f.get("role") for f in findings)
    classed = [_classed(f) for f in findings]
    current = reevaluate(plan)
    assessed = readiness is not None
    if not assessed and not current.guides:
        # Every actionable call still gets exactly one entry, from today's rules.
        current = cover(current, classed)
    version = engine_of(score)
    older = version if version and _base(version) != _base(analyzer_version()) else ""
    return RunData(
        findings=classed,
        plan=current,
        readiness=readiness,
        assessed=assessed,
        roles_measured=roles_measured or source == "cdg",
        older_engine=older,
        findings_source=source,
    )
