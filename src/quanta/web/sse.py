"""Server-Sent Events for job progress (§5.2.3).

SSE, not WebSocket: the stream is strictly server→client, and SSE is plain HTTP with
automatic reconnection and ``Last-Event-ID`` replay built into every browser (§5.2.1).
Bidirectional framing and heartbeats would be machinery for a one-way stream.

Event ids are the per-job buffer index, so reconnection resumes exactly rather than
approximately, and the API still performs no analysis work — it reads a list.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

from quanta.web.jobs import Job, JobEvent, JobRegistry

#: Comment frames keep intermediaries from closing an idle connection.
_KEEPALIVE = ": keepalive\n\n"
_KEEPALIVE_INTERVAL_S = 15.0

#: The failure event is named ``failed``, not ``error``. ``EventSource`` already dispatches
#: a built-in ``error`` event for transport problems, so a server-sent ``event: error``
#: would be indistinguishable from a dropped connection on the client.
TERMINAL_EVENTS = {"done", "failed"}


def format_event(event: JobEvent) -> str:
    payload = json.dumps(event.data, sort_keys=True)
    return f"id: {event.id}\nevent: {event.event}\ndata: {payload}\n\n"


async def stream(
    job: Job,
    registry: JobRegistry,
    last_event_id: int = 0,
    replay_delays: list[int] | None = None,
) -> AsyncIterator[str]:
    """Yield SSE frames for ``job``, resuming after ``last_event_id``.

    ``replay_delays`` paces a cached run so the pipeline is watchable; a live run has no
    delays and streams as fast as the analyzer produces events.
    """
    cursor = last_event_id
    step_index = 0
    idle_since = asyncio.get_event_loop().time()

    while True:
        registry.drain()

        pending = [e for e in job.events if e.id > cursor]
        for event in pending:
            if replay_delays is not None and event.event == "step":
                delay_ms = (
                    replay_delays[step_index]
                    if step_index < len(replay_delays)
                    else _fallback_delay()
                )
                step_index += 1
                await asyncio.sleep(delay_ms / 1000)

            yield format_event(event)
            cursor = event.id
            idle_since = asyncio.get_event_loop().time()

            if event.event in TERMINAL_EVENTS:
                return

        # A live job that has finished but produced no terminal event (e.g. the pool died)
        # must still close, or the client waits forever.
        if job.status in {"succeeded", "failed"} and not pending:
            remaining = [e for e in job.events if e.id > cursor]
            if not remaining:
                return

        now = asyncio.get_event_loop().time()
        if now - idle_since >= _KEEPALIVE_INTERVAL_S:
            yield _KEEPALIVE
            idle_since = now

        await asyncio.sleep(0.05)


def _fallback_delay() -> int:
    return 200


def parse_last_event_id(raw: str | None) -> int:
    """Tolerate a missing or malformed header by starting from the beginning."""
    if not raw:
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0
