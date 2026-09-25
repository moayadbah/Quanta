"""Record the workspace sample: one real repository, run once through the real pipeline.

    uv run python scripts/record_sample.py [https://github.com/owner/name]

Runs ``analyze_repository`` exactly as the worker does (validate, resolve, clone at the head
commit, parse, graph, score, readiness, proposals, render, cleanup), keeps every artifact it
wrote, and records every event it emitted with its time offset. ``quanta.web.sample``
replays those events in order, so the sample streams like the live scan it was.

Not part of the shipped CLI. Run it again only to refresh the sample.
"""

from __future__ import annotations

import json
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from quanta.core.analyze import STEP_TITLES, analyze_repository, write_artifacts
from quanta.core.models import StepRecord

DEFAULT = "https://github.com/tlsfuzzer/python-ecdsa"
TARGET = Path(__file__).resolve().parents[1] / "demo" / "sample"


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    events: list[dict[str, Any]] = []
    started = time.monotonic()

    def record(kind: str, data: dict[str, Any]) -> None:
        events.append(
            {"at_ms": int((time.monotonic() - started) * 1000), "event": kind, "data": data}
        )

    record("status", {"status": "running"})
    record("plan", {"steps": [{"id": sid, "title": title} for sid, title in STEP_TITLES]})

    def progress(step: StepRecord) -> None:
        record("step", step.model_dump(mode="json"))

    outcome = analyze_repository(url, progress=progress, on_event=record)
    record("done", {"status": "succeeded", "agility_score": outcome.score.agility_score})

    if TARGET.exists():
        shutil.rmtree(TARGET)
    TARGET.mkdir(parents=True)
    write_artifacts(outcome, TARGET)
    (TARGET / "events.json").write_text(
        json.dumps({"events": events}, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    provenance = outcome.score.provenance
    manifest = {
        "repo": provenance.repo,
        "commit_sha": provenance.commit_sha,
        "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "duration_ms": events[-1]["at_ms"],
        "events": len(events),
        "findings": len(outcome.findings),
        "patches": sum(len(f.changes) for f in outcome.fixes.files),
        "refusals": len(outcome.fixes.skipped),
        "guided_sites": sum(len(g.sites) for g in outcome.fixes.guides),
        "verdict": outcome.readiness.verdict if outcome.readiness else None,
    }
    (TARGET / "sample.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
