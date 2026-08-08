"""Regenerate the cached demo corpus (ADR-022).

    uv run python scripts/build_demo_corpus.py

Each entry is a real public repository analysed at whatever commit is current when this
runs, then committed. The pinned SHA travels in every artifact's provenance, so a cached
example is reproducible: anyone can clone at that SHA and re-derive the same numbers.

Not part of the shipped CLI surface (§9.3) — this is a maintenance script, run rarely.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from quanta.core.analyze import analyze_repository, write_artifacts
from quanta.core.models import StepRecord

CORPUS = Path(__file__).resolve().parents[1] / "demo" / "corpus"

#: Chosen for contrast across the score's range, not for flattering results.
ENTRIES = [
    {
        "slug": "pyjwt",
        "url": "https://github.com/jpadilla/pyjwt",
        "title": "PyJWT",
        "blurb": "JSON Web Token library. Cryptography reached directly from many modules.",
    },
    {
        "slug": "python-jose",
        "url": "https://github.com/mpdavis/python-jose",
        "title": "python-jose",
        "blurb": "JOSE implementation. Fewer sites, but still no common wrapper.",
    },
    {
        "slug": "click",
        "url": "https://github.com/pallets/click",
        "title": "Click",
        "blurb": "CLI toolkit with no cryptography at all — the correct answer is 100.",
    },
]


def build(entry: dict[str, str]) -> None:
    target = CORPUS / entry["slug"]
    print(f"  analysing {entry['url']} ...", flush=True)

    outcome = analyze_repository(entry["url"])

    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    write_artifacts(outcome, target)

    steps: list[StepRecord] = list(outcome.meta.steps)
    manifest = {
        "title": entry["title"],
        "blurb": entry["blurb"],
        "sites": len(outcome.detection.crypto_calls),
        "repo": outcome.score.provenance.repo,
        "commit_sha": outcome.score.provenance.commit_sha,
        "agility_score": outcome.score.agility_score,
        "steps": len(steps),
    }
    (target / "example.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(
        f"    {outcome.score.provenance.repo} @ {outcome.score.provenance.commit_sha[:12]}"
        f"  score {outcome.score.agility_score:.1f}"
        f"  sites {len(outcome.detection.crypto_calls)}"
        f"  steps {len(steps)}",
        flush=True,
    )


def main() -> int:
    CORPUS.mkdir(parents=True, exist_ok=True)
    print("Building demo corpus")
    for entry in ENTRIES:
        build(entry)
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
