"""The numbers page's figures for v5 and v9, recomputed from the round results (no new measurement).

    python evidence/figures_v9.py

Reads, without changing them:
- evidence/r9/accuracy-r9.json     H9  (30 repositories)
- evidence/r10/accuracy-r10.json   H10 (30 repositories)
- evidence/r11/accuracy-r11.json   H11 (60 repositories)
- evidence/r11/decision-r11.json   the pooled A+B figures, to cross-check
- evidence/r9/time-cost-v5.json and time-cost-v9.json
                                    the R4 time-cost method (r4/TIME-COST-METHOD.md) re-run on the
                                    same 60 repositories and the same machine, once per engine

Writes `evidence/figures-v9.json`: every figure as found / total, its rate, a Wilson 95% interval,
and the SHA-256 of each input, so each number on the page can be traced to a file.

Class A is a call into a crypto library; PK+TLS is the kinds public_key, key_handling and tls.
"Other crypto" is class A minus PK+TLS. Every set was held out from both engines (PROTOCOL-R11 D3).
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent  # evidence/
ROOT = HERE.parent
SETS = {
    "H9": HERE / "r9" / "accuracy-r9.json",
    "H10": HERE / "r10" / "accuracy-r10.json",
    "H11": HERE / "r11" / "accuracy-r11.json",
}
DECISION = HERE / "r11" / "decision-r11.json"
TIME = {
    "v5": HERE / "r9" / "time-cost-v5.json",
    "v9": HERE / "r9" / "time-cost-v9.json",
}


def wilson(k: int, n: int, z: float = 1.959964) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(c - h, 4), round(c + h, 4)]


def rate(k: int, n: int) -> dict:
    return {
        "found": k,
        "total": n,
        "rate": round(k / n, 4),
        "percent": round(100 * k / n, 1),
        "ci": wilson(k, n),
    }


def engine(data: dict, name: str) -> dict:
    return next(v for k, v in data.items() if k.startswith(name + " "))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    sets = {s: load(p) for s, p in SETS.items()}
    figures: dict = {}
    for name in ("v5", "v9"):
        sums = {m: [0, 0] for m in ("recall_A", "pktls_A", "recall_AB", "precision")}
        per_set = {}
        for s, data in sets.items():
            pooled = engine(data, name)["pooled"]
            per_set[s] = {m: [pooled[m]["found"], pooled[m]["total"]] for m in sums}
            for m in sums:
                sums[m][0] += pooled[m]["found"]
                sums[m][1] += pooled[m]["total"]
        a, pk = sums["recall_A"], sums["pktls_A"]
        h11_pk = per_set["H11"]["pktls_A"]
        figures[name] = {
            "other_crypto_A": rate(a[0] - pk[0], a[1] - pk[1]),  # card 1
            "pktls_A": rate(*pk),  # card 2
            "pktls_A_H11_only": rate(*h11_pk),  # card 2, the line about the latest sample
            "precision": rate(*sums["precision"]),  # card 3
            "real_crypto_reported": sums["precision"][0],  # card 3, the green line (v9 minus v5)
            "recall_A": rate(*a),
            "recall_AB": rate(*sums["recall_AB"]),  # the scope line
            "per_set": per_set,
        }
        tc = load(TIME[name])["summary"]
        figures[name]["time_cost"] = {
            k: tc[k]
            for k in (
                "repositories",
                "ruleset",
                "quanta_seconds_median",
                "saved_hours_median",
                "saved_usd_median",
                "overdue_sites",
            )
        }

    # cross-check against the published R11 decision (A+B and precision)
    dec = load(DECISION)["independent_pooled"]
    for name in ("v5", "v9"):
        d = dec[f"{name} on H9+H10+H11"]
        for m in ("recall_AB", "precision"):
            got = figures[name][m]
            if (got["found"], got["total"]) != (d[m]["found"], d[m]["total"]):
                raise SystemExit(f"{name} {m}: {got} does not match decision-r11.json {d[m]}")

    v5, v9 = figures["v5"], figures["v9"]
    page = {
        "card1_other_crypto": {
            "v5": v5["other_crypto_A"]["percent"],
            "v9": v9["other_crypto_A"]["percent"],
            "points": round(v9["other_crypto_A"]["percent"] - v5["other_crypto_A"]["percent"], 1),
        },
        "card2_pktls": {
            "v5": v5["pktls_A"]["percent"],
            "v9": v9["pktls_A"]["percent"],
            "points": round(v9["pktls_A"]["percent"] - v5["pktls_A"]["percent"], 1),
            "v9_latest_sample_H11": v9["pktls_A_H11_only"]["percent"],
        },
        "card3_precision": {
            "v5": v5["precision"]["percent"],
            "v9": v9["precision"]["percent"],
            "results_v5": v5["precision"]["total"],
            "results_v9": v9["precision"]["total"],
            "real_v5": v5["real_crypto_reported"],
            "real_v9": v9["real_crypto_reported"],
            "more_real_calls": v9["real_crypto_reported"] - v5["real_crypto_reported"],
        },
        "card4_hours": {
            "v5": v5["time_cost"]["saved_hours_median"],
            "v9": v9["time_cost"]["saved_hours_median"],
        },
        "card4_scan_seconds": {
            "v5": v5["time_cost"]["quanta_seconds_median"],
            "v9": v9["time_cost"]["quanta_seconds_median"],
        },
        "card5_usd": {
            "v5": v5["time_cost"]["saved_usd_median"],
            "v9": v9["time_cost"]["saved_usd_median"],
        },
        "card6_overdue": {
            "v5": v5["time_cost"]["overdue_sites"],
            "v9": v9["time_cost"]["overdue_sites"],
        },
        "scope_recall_AB": {"v5": v5["recall_AB"]["percent"], "v9": v9["recall_AB"]["percent"]},
        "class_A_units": v9["recall_A"]["total"],
    }
    out = {
        "_about": __doc__.strip().splitlines()[0],
        "page": page,
        "figures": figures,
        "inputs": {
            p.relative_to(ROOT).as_posix(): sha(p)
            for p in [*SETS.values(), DECISION, *TIME.values()]
        },
    }
    (HERE / "figures-v9.json").write_text(
        json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(page, indent=1, ensure_ascii=False))
