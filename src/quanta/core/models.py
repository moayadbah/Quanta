"""Artifact contracts for ``cdg.json``, ``score.json`` and ``meta.json`` (§5.1.4).

These models are the interface between the analyzer, the report, the experiment and the
web tier. Everything downstream depends on them, which is why §11.1 places them at step 3
— before any producer exists.

Two invariants are enforced here rather than left to callers:

* **Determinism (NFR-03).** The same provenance triple must yield *byte-identical*
  ``cdg.json`` and ``score.json``. Timestamps and durations therefore live in
  ``meta.json`` only, and :func:`dump_canonical_json` fixes key order and float
  formatting. Unrounded floats are a real determinism hazard: the same computation can
  differ in the last bit across platforms, and ``repr`` would faithfully print the
  difference.
* **Traceability (PROC-08).** Every deduction carries at least one ``file:line``
  citation. A score without a traceable cause is a defect, so the model refuses to
  construct one.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0"

#: Decimal places retained on every emitted float. Six is far beyond meaningful precision
#: for a 0-100 score and well inside the range where float64 is exact across platforms.
_FLOAT_PRECISION = 6

#: ``path/to/file.py:123``. Validated rather than trusted because citations are built from
#: attacker-controlled file names and are interpolated into the report (T5).
_CITATION_RE = re.compile(r"^[^\x00-\x1f:]{1,512}:\d{1,9}$")


def _round(value: float) -> float:
    return round(value, _FLOAT_PRECISION)


Rounded = Annotated[float, Field(json_schema_extra={"x-rounded": True})]

NodeKind = Literal["crypto_call", "algo_literal", "config_read", "function", "module"]
EdgeKind = Literal["binding", "value_flow", "import", "call"]
Confidence = Literal["high", "low"]
SiteSource = Literal["static", "cbom"]


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# ---------------------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------------------


class Provenance(_Base):
    """The reproducibility anchor and cache key (INGEST-04).

    Detection output is only meaningful relative to the ruleset that produced it, so the
    ruleset version is part of the triple rather than incidental metadata.
    """

    repo: str
    commit_sha: str
    analyzer_version: str
    crypto_ruleset_version: str

    def cache_key(self) -> str:
        """``sha256("owner/name@sha#analyzer_version")`` — the ``analysis_cache`` key."""
        import hashlib

        material = f"{self.repo}@{self.commit_sha}#{self.analyzer_version}"
        return hashlib.sha256(material.encode()).hexdigest()


# ---------------------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------------------


class CryptoSite(_Base):
    """One detected cryptographic usage site — the unit annotators classify (§5.1.5)."""

    site_id: str
    file: str
    line: int
    col: int
    qualified_name: str
    kind: NodeKind = "crypto_call"
    algorithm: str | None = None
    module: str
    source: SiteSource = "static"
    #: True when the matched name is in ``WEAK_ALGORITHMS`` or ``QUANTUM_VULNERABLE``.
    weak: bool = False
    quantum_vulnerable: bool = False
    #: Qualified name of the function enclosing this site, if any. Used to attach the
    #: site to its scope in the CDG without re-walking the tree.
    enclosing_function: str | None = None
    #: For ``algo_literal`` and ``config_read`` nodes: the ``crypto_call`` they select for.
    parent_site_id: str | None = None

    @property
    def citation(self) -> str:
        return f"{self.file}:{self.line}"


class UnparseableFile(_Base):
    """A file LibCST could not parse (PROC-02).

    Recorded with a reason and excluded from the denominator, **not** from the report —
    a silently dropped file is an unmeasured false negative.
    """

    file: str
    reason: str


# ---------------------------------------------------------------------------------------
# Truncation and coverage
# ---------------------------------------------------------------------------------------


class TruncationRecord(_Base):
    """A declared truncation (INGEST-08). Exceeding a budget is never a silent drop."""

    reason: str
    limit: int
    observed: int


class Coverage(_Base):
    files_scanned: int = 0
    files_unparseable: int = 0
    truncated: bool = False


# ---------------------------------------------------------------------------------------
# CDG
# ---------------------------------------------------------------------------------------


class CdgNode(_Base):
    id: str
    kind: NodeKind
    file: str
    line: int
    col: int
    qualified_name: str
    module: str
    source: SiteSource = "static"
    algorithm: str | None = None


class CdgEdge(_Base):
    source: str
    target: str
    kind: EdgeKind
    confidence: Confidence

    @field_validator("confidence")
    @classmethod
    def _call_edges_are_always_low(cls, v: Confidence, info: Any) -> Confidence:
        """DoD-C3: every ``call`` edge is tagged ``confidence: "low"``.

        One-hop qualified-name resolution is an approximation of value flow, and "low" is
        the honest label for it (§5.3.2). Enforced here so no producer can forget.
        """
        if info.data.get("kind") == "call" and v != "low":
            raise ValueError("call edges must be confidence='low' — see §5.3.2 / DoD-C3")
        return v


# ---------------------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------------------


class Factor(_Base):
    """One of the four Agility Score factors (§5.3.3)."""

    raw: int | float | bool | str
    normalised: Rounded
    weight: Rounded
    contribution: Rounded

    @field_validator("normalised", "weight", "contribution", mode="after")
    @classmethod
    def _quantise(cls, v: float) -> float:
        return _round(v)

    @field_validator("normalised")
    @classmethod
    def _normalised_in_unit_interval(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"normalised factor must lie in [0, 1], got {v}")
        return v


class Deduction(_Base):
    """Points removed from a perfect score, with the evidence that justifies them."""

    factor: str
    points: Rounded
    reason: str
    citations: tuple[str, ...]

    @field_validator("points", mode="after")
    @classmethod
    def _quantise(cls, v: float) -> float:
        return _round(v)

    @field_validator("citations")
    @classmethod
    def _must_cite_something_wellformed(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        """PROC-08 / DoD-C4: at least one syntactically valid ``file:line`` citation."""
        if not v:
            raise ValueError("every deduction requires >=1 file:line citation (PROC-08)")
        for c in v:
            if not _CITATION_RE.match(c):
                raise ValueError(f"malformed citation {c!r}; expected 'path/to/file.py:123'")
        return v


class Recommendation(_Base):
    action: str
    estimated_score_gain: Rounded
    affected_sites: int

    @field_validator("estimated_score_gain", mode="after")
    @classmethod
    def _quantise(cls, v: float) -> float:
        return _round(v)


class ScoreReport(_Base):
    """``score.json`` — the single contract consumed by the frontend, report and experiment."""

    schema_version: str = SCHEMA_VERSION
    provenance: Provenance
    agility_score: Rounded
    factors: dict[str, Factor]
    deductions: tuple[Deduction, ...] = ()
    recommendations: tuple[Recommendation, ...] = ()
    coverage: Coverage = Coverage()

    @field_validator("agility_score", mode="after")
    @classmethod
    def _quantise_and_bound(cls, v: float) -> float:
        if not 0.0 <= v <= 100.0:
            raise ValueError(f"agility score must lie in [0, 100], got {v}")
        return _round(v)


# ---------------------------------------------------------------------------------------
# Pipeline trace
# ---------------------------------------------------------------------------------------

StepStatus = Literal["pending", "running", "done", "skipped", "failed"]


class StepEvidence(_Base):
    """One labelled fact about what a pipeline step did.

    ``ok`` marks a control that either held or did not — rendered as a tick or a cross.
    Leave it ``None`` for a plain measurement, where a tick would imply a judgement the
    analyzer is not making.
    """

    label: str
    value: str
    ok: bool | None = None


class StepRecord(_Base):
    """One step of the analysis, with the evidence that justifies its summary.

    The score has carried citations since PROC-08, but the *pipeline* has not been
    traceable at all: until now the only record of what happened between a URL and a
    number was a phase name and a counter. This closes that gap, which serves auditability
    as much as it serves the demo — a reviewer asking "what did it actually check before
    it made a network call?" now has a machine-readable answer.
    """

    id: str
    title: str
    status: StepStatus = "pending"
    summary: str = ""
    evidence: tuple[StepEvidence, ...] = ()
    duration_ms: int = 0


# ---------------------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------------------


class AnalysisMeta(BaseModel):
    """``meta.json`` — provenance, timings, truncation and the pipeline trace (§5.1.3).

    Timings live here and **only** here. Putting a duration inside ``score.json`` would
    break the byte-identical requirement in NFR-03 on the very next run — which is also
    why the trace, whose steps carry durations, belongs in this file and not that one.
    """

    model_config = ConfigDict(extra="forbid")

    provenance: Provenance
    started_at: str
    finished_at: str
    duration_ms: int
    phase_durations_ms: dict[str, int] = Field(default_factory=dict)
    truncation: TruncationRecord | None = None
    truncations: tuple[TruncationRecord, ...] = ()
    cbom_sha256: str | None = None
    cbom_unlocated: int = 0
    unparseable: tuple[UnparseableFile, ...] = ()
    files_scanned: int = 0
    sites_detected: int = 0
    steps: tuple[StepRecord, ...] = ()


# ---------------------------------------------------------------------------------------
# Deterministic serialisation
# ---------------------------------------------------------------------------------------


def dump_canonical_json(payload: Any) -> str:
    """Serialise to the canonical form required by NFR-03.

    Sorted keys, fixed separators, UTF-8 preserved, trailing newline. Pydantic models are
    converted through ``model_dump`` first so validators (rounding, citation checks) have
    already run.
    """
    if isinstance(payload, BaseModel):
        payload = payload.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def write_canonical_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_canonical_json(payload), encoding="utf-8")
