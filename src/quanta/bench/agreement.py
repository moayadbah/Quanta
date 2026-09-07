"""Agreement and separate precision/recall over fixed, double-classified candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from quanta.bench.dataset import read_dataset, read_jsonl
from quanta.bench.worksheet import LABELS
from quanta.errors import Reject


def _labels(path: Path, expected: set[str]) -> dict[str, str]:
    rows = read_jsonl(path)
    labels = {r.get("site_id"): r.get("label") for r in rows}
    if len(rows) != len(labels) or set(labels) != expected or not set(labels.values()) <= LABELS:
        raise Reject("BENCHMARK_INVALID", f"missing, duplicate or invalid labels in {path.name}")
    return {str(k): str(v) for k, v in labels.items()}


def _agreement(a1: list[int], a2: list[int]) -> dict[str, Any]:
    import krippendorff
    import numpy as np

    if not a1:
        raise Reject("BENCHMARK_INVALID", "cannot calculate agreement on an empty candidate list")
    alpha: float | None
    try:
        alpha = float(
            krippendorff.alpha(reliability_data=np.array([a1, a2]), level_of_measurement="nominal")
        )
        if not np.isfinite(alpha):
            alpha = None
    except ValueError:
        alpha = None
    return {
        "n": len(a1),
        "krippendorff_alpha": alpha,
        "alpha_note": "undefined for a constant label distribution" if alpha is None else None,
        "exact_agreement_pct": 100 * sum(x == y for x, y in zip(a1, a2, strict=True)) / len(a1),
    }


def agreement(root: Path, *, require_adjudication: bool = False) -> dict[str, Any]:
    reports: dict[str, Any] = {}
    all_a1: list[int] = []
    all_a2: list[int] = []
    tp = fp = fn = 0
    unresolved = 0
    for repo in read_dataset(root / "dataset.lock.json").repositories:
        candidates = read_jsonl(root / "candidates" / f"{repo.slug}.jsonl")
        ids = [r["site_id"] for r in candidates]
        if len(ids) != len(set(ids)):
            raise Reject("BENCHMARK_INVALID", "duplicate candidate ids")
        a1 = _labels(root / "labels" / f"{repo.slug}.a1.jsonl", set(ids))
        a2 = _labels(root / "labels" / f"{repo.slug}.a2.jsonl", set(ids))
        v1, v2 = [int(a1[i] == "crypto") for i in ids], [int(a2[i] == "crypto") for i in ids]
        reports[repo.repo] = _agreement(v1, v2)
        all_a1.extend(v1)
        all_a2.extend(v2)
        differing = {sid for sid in ids if a1[sid] != a2[sid]}
        adjudication = root / "adjudication" / f"{repo.slug}.jsonl"
        resolved = _labels(adjudication, differing) if adjudication.exists() else {}
        if require_adjudication and differing - resolved.keys():
            raise Reject("BENCHMARK_INVALID", f"unresolved disagreements for {repo.repo}")
        for candidate in candidates:
            sid = candidate["site_id"]
            if sid in differing and sid not in resolved:
                unresolved += 1
                continue
            gold = resolved.get(sid, a1[sid]) == "crypto"
            prediction = bool(candidate["detected"])
            tp += int(gold and prediction)
            fp += int(not gold and prediction)
            fn += int(gold and not prediction)
    return {
        "overall": _agreement(all_a1, all_a2),
        "repositories": reports,
        "detection": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "unresolved": unresolved,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "provisional": unresolved > 0,
            "scope": "Enumerated calls only; excluded files and non-call crypto are not measured.",
        },
    }
