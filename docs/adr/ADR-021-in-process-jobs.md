# ADR-021 — In-memory job registry with per-job child processes

**Status:** Superseded by ADR-023 (durable SQLite worker). Retained as historical context.
**Date:** 2026-08-08
**Amends §3.5 and ADR-006. Does not satisfy DoD-W2 or M8's "worker process" clause.**

## Context

§3.5 selects a separate worker process polling a SQLite `jobs` table, with an atomic claim
and a `claimed_at` staleness sweep. ADR-006 accepts it. DoD-W2 tests it: a job must survive
an API restart, a killed worker's job must be re-queued after `claim_ttl_s`, and
`max_attempts` must be respected.

That design is right for the deployed service. It is a substantial amount of machinery for
a build whose immediate purpose is a demonstration, and it was consciously traded away.

## Decision

Hold jobs in memory in the API process. Run each analysis in its **own spawned child
process**, streaming progress back over a `multiprocessing.Queue`.

### Why a child process rather than a thread

§3.5 rejects `FastAPI BackgroundTasks` because CPU-bound parsing starves the event loop.
That objection applies equally to a thread pool: the LibCST visitor is Python and holds the
GIL, so SSE delivery would stutter. Live progress **is** the demo, so it must not.

§3.5 rates `ProcessPoolExecutor` "better — real isolation". Two things pushed this to a
per-job process instead of a pool:

- A `multiprocessing.Queue` cannot be pickled into a pool task —
  `Queue objects should only be shared between processes through inheritance`. Passing one
  to `Process(args=…)` is the supported path. (Found by running it, not by reading.)
- §4.2 describes a per-job analyzer child that carries its own `setrlimit` caps and can be
  killed by a watchdog. A pooled worker is reused across jobs, which is incompatible with
  both. The per-job process is the shape the eventual sandbox needs.

## Consequences — stated plainly

- **Jobs do not survive an API restart.** There is no durable queue and no staleness sweep.
  **DoD-W2 is not met, and M8 is not complete.**
- Analysis does not starve the event loop; SSE stays smooth.
- A watchdog terminates a child exceeding `max_job_seconds`, and a liveness check converts
  a crashed child into a terminal `failed` event rather than a stream that never closes.
- No SQLite, no schema, no `analysis_cache` — so repeat submissions are re-analysed rather
  than deduplicated by provenance triple (INGEST-10 is not implemented either).

## What keeps the deviation cheap to undo

The **HTTP contract (§5.2.2) and the event format are exactly what a durable worker would
produce**. Job ids are UUIDv4 capability URLs; events carry monotonic ids and support
`Last-Event-ID` resume; status payloads carry `status`, `phase` and `progress`. Restoring
§3.5 means replacing `web/jobs.py` and adding `web/db.py` — the routes, the SSE layer and
the frontend are unaffected.

## Revisit trigger

Any of: the service is left running unattended, a demo needs a job to survive a restart, a
second concurrent user appears, or work resumes on M8/DoD-W2 for the thesis deliverable.
