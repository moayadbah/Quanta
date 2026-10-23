"""Rebuild the public start-to-today counts from the original source and current code.

Run from a full Git checkout: ``uv run python evidence/project_progress.py``.
This does not rerun or compare accuracy benchmarks. Their existing results are kept.
"""

from __future__ import annotations

import ast
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from quanta.core.ruleset_v2 import SITE_RULES  # noqa: E402

BASELINE = "a0cdc2f95a4ba6093b7bd8aa8ae5366d536cc3c9"
BASELINE_PATH = "src/quanta/core/rules.py"


def build() -> dict:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is required to read the original project milestone.")
    original = subprocess.check_output([git, "show", f"{BASELINE}:{BASELINE_PATH}"], cwd=ROOT)
    tree = ast.parse(original)
    calls = next(
        sorted(ast.literal_eval(node.value.args[0]))
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "CRYPTO_QUALIFIED_NAMES"
        and isinstance(node.value, ast.Call)
    )
    guides = json.loads((ROOT / "config/migrations.json").read_text())["guides"]
    baseline = {
        "rules": len(calls),
        "namespaces": len({call.split(".")[0] for call in calls}),
        "guides": 0,
    }
    current = {
        "rules": len(SITE_RULES),
        "namespaces": len({call.split(".")[0] for call in SITE_RULES}),
        "guides": len(guides),
    }
    return {
        "_about": "Source inventory counts, not a claim about detection accuracy or speed.",
        "baseline_commit": BASELINE,
        "baseline_source": BASELINE_PATH,
        "baseline_source_sha256": hashlib.sha256(original).hexdigest(),
        "baseline_named_calls": calls,
        "baseline_guides_note": "The first milestone has no migration guide catalog or proposals.",
        "baseline": baseline,
        "current": current,
        "current_sources": ["src/quanta/core/ruleset_v2.py", "config/migrations.json"],
        "current_source_sha256": {
            path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            for path in ("src/quanta/core/ruleset_v2.py", "config/migrations.json")
        },
        "accuracy_note": (
            "No equivalent held-out accuracy result is published for the original milestone. "
            "The current figures remain sourced from evidence/figures-v9.json. "
            "The earlier engine in that file is not the original project baseline."
        ),
    }


if __name__ == "__main__":
    result = build()
    (ROOT / "evidence/project-progress.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    target = ROOT / "src/quanta/web/static/evidence.json"
    public = json.loads(target.read_text())
    public["progress"] = {
        "baseline": result["baseline"],
        "current": result["current"],
        "sources": [
            {
                "id": "first",
                "url": f"https://github.com/moayadbah/Quanta/blob/{BASELINE}/{BASELINE_PATH}",
            },
            {
                "id": "rules",
                "url": "https://github.com/moayadbah/Quanta/blob/main/src/quanta/core/ruleset_v2.py",
            },
            {
                "id": "guides",
                "url": "https://github.com/moayadbah/Quanta/blob/main/config/migrations.json",
            },
            {
                "id": "counts",
                "url": "https://github.com/moayadbah/Quanta/blob/main/evidence/project-progress.json",
            },
        ],
    }
    target.write_text(json.dumps(public, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"baseline": result["baseline"], "current": result["current"]}))
