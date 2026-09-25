"""Agility Score entry point. The definition lives in :mod:`quanta.core.metric_v2`.

Metric v1 (node-cut isolation, saturating propagation, tests counted as architecture) is
retired: round two showed it could not reward the refactor it recommended (Master Plan
22.7). The tag ``saif-2026-registration`` keeps v1 reproducible for anyone who needs it.

Weights are **pre-registered** (``weights-v1``) and loaded from configuration; their sum
is asserted, never renormalised. Every deduction carries at least one ``file:line``
citation, and the model layer refuses to construct one without it (PROC-08).
"""

from __future__ import annotations

import networkx as nx

from quanta.config import Settings, get_settings
from quanta.core.detect import DetectionResult
from quanta.core.metric_v2 import compute_v2
from quanta.core.models import Coverage, Provenance, ScoreReport


def compute_score(
    detection: DetectionResult,
    graph: nx.DiGraph,
    provenance: Provenance,
    coverage: Coverage,
    settings: Settings | None = None,
) -> ScoreReport:
    """Gate, then compute metric-v2 with a cited deduction for every point removed."""
    return compute_v2(detection, graph, provenance, coverage, settings or get_settings())
