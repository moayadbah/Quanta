"""Exercise the installed service; optionally include real public GitHub ingestion."""

from __future__ import annotations

import argparse
import json
import time
from http.client import HTTPConnection

parser = argparse.ArgumentParser()
parser.add_argument("--live", action="store_true")
args = parser.parse_args()


def request(path: str, body: dict[str, str] | None = None) -> dict[str, object]:
    payload = json.dumps(body).encode() if body is not None else None
    connection = HTTPConnection("127.0.0.1", 8000, timeout=15)
    try:
        connection.request(
            "POST" if body is not None else "GET",
            "/api/v1" + path,
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        if response.status >= 400:
            raise RuntimeError(f"Service returned HTTP {response.status}")
        return json.loads(response.read())
    finally:
        connection.close()


for _ in range(60):
    try:
        health = request("/healthz")
        if health.get("worker_heartbeat_age_s") is not None:
            break
    except (OSError, RuntimeError):
        pass
    time.sleep(1)
else:
    raise SystemExit("Service and worker did not become healthy.")

cached = request("/examples/click/replay", {})
job_id = cached["job_id"]
if request(f"/analyses/{job_id}")["status"] != "succeeded":
    raise SystemExit("Cached analysis did not succeed.")
if request(f"/analyses/{job_id}/score")["agility_score"] != 100:
    raise SystemExit("Cached score did not match.")

if args.live:
    created = request("/analyses", {"repo_url": "https://github.com/pallets/click"})
    job_id = created["job_id"]
    for _ in range(150):
        status = request(f"/analyses/{job_id}")
        if status["status"] in {"succeeded", "failed", "timeout"}:
            break
        time.sleep(2)
    else:
        raise SystemExit("Public repository analysis exceeded smoke-test timeout.")
    if status["status"] != "succeeded":
        raise SystemExit(f"Public repository analysis failed: {status.get('error_code')}")
    if request(f"/analyses/{job_id}/score")["provenance"]["commit_sha"] == "0" * 40:
        raise SystemExit("Public run was not pinned.")
    # Repeat submission must return the same completed analysis, with no second clone.
    repeat = request("/analyses", {"repo_url": "https://github.com/pallets/click"})
    if repeat["job_id"] != job_id:
        raise SystemExit("Provenance cache did not reuse the result.")
print("Service smoke test passed.")
