"""Regenerate the cached demo corpus (ADR-022).

    uv run python scripts/build_demo_corpus.py

Each entry is a real public repository analysed through the product's own pipeline
(validate, resolve, clone, walk, parse, graph, score, render, cleanup) at whatever commit
is the branch head when this runs. The resolved SHA travels in every artifact's
provenance and in ``example.json``, so anyone can clone at that SHA and re-derive the
same numbers.

Titles and descriptions are not stored here: every visible string lives in
``content/site.json`` under ``examples.<slug>``.

Not part of the shipped CLI surface (§9.3). This is a maintenance script, run rarely.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from quanta.core.analyze import analyze_repository, write_artifacts

CORPUS = Path(__file__).resolve().parents[1] / "demo" / "corpus"

#: Chosen to show every kind of answer, not flattering ones: a scored library, a
#: library where the hash fix is refused because MD5 is part of a protocol, a library
#: whose score is withheld, and a project with no cryptography at all.
ENTRIES = [
    ("pyjwt", "https://github.com/jpadilla/pyjwt"),
    ("requests", "https://github.com/psf/requests"),
    ("python-jose", "https://github.com/mpdavis/python-jose"),
    ("click", "https://github.com/pallets/click"),
]


def build(slug: str, url: str) -> None:
    target = CORPUS / slug
    print(f"  analysing {url} ...", flush=True)
    outcome = analyze_repository(url)
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    write_artifacts(outcome, target)
    score = outcome.score
    manifest = {
        "repo": score.provenance.repo,
        "commit_sha": score.provenance.commit_sha,
        "status": score.status,
        "agility_score": score.agility_score,
        "sites": len(outcome.detection.crypto_calls),
        "findings": len(outcome.findings),
        "proposals": sum(len(f.changes) for f in outcome.fixes.files),
        "refusals": len(outcome.fixes.skipped),
        "steps": len(outcome.meta.steps),
    }
    (target / "example.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"    {json.dumps(manifest, sort_keys=True)}", flush=True)


def main() -> int:
    CORPUS.mkdir(parents=True, exist_ok=True)
    print("Building demo corpus")
    for entry in ENTRIES:
        build(*entry)
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
