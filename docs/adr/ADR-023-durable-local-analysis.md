# ADR-023: Durable local analysis replaces the in-memory demo queue

Status: Accepted. Supersedes ADR-021. Retains the static frontend in ADR-020.

## Decision

Restore the separate worker and SQLite queue from the technical document. API requests
resolve metadata, enqueue pinned work, and read durable events and artifacts. Workers
claim under a write transaction; `(job_id, worker_id, attempts)` fences progress and
publication so an expired attempt cannot finish its replacement. The concurrency limit
is global across worker processes. A watchdog works without a browser or API request.

Use Python's SQLite interface for the document's explicit transactional SQL. SQLModel
remains in the declared dependency set, but wrapping these four small tables in ORM
classes provides no additional validation. Add a worker-heartbeat table because an idle
worker has no running job on which to record its health. Jobs retain the resolved default
branch and size for accurate provenance traces; cached demo replays are flagged separately
from live provenance-cache hits. Events use the database's global sequence, with exact
Last-Event-ID replay and terminal `done` / `error` events.

Artifacts are atomically replaced inside UUID directories. Source and intermediate output
stay in per-attempt scratch until the owning supervisor publishes a successful run.
The Compose worker uses a bounded `noexec,nosuid,nodev` tmpfs, a read-only root, non-root
UID, dropped capabilities and no-new-privileges. API shutdown leaves worker jobs intact.

## Isolation boundary and remaining limitation

Linux child processes have resource limits, a parent-death signal, and a libseccomp filter
that rejects new sockets, connections on existing sockets, sends and io_uring after
cloning. Compose requires these controls and fails closed if installation fails.
`libseccomp2` is a system dependency required by NFR-04 and section 7.3; no additional
Python dependency is introduced. Native macOS and Windows have the process watchdog but
cannot provide the Linux controls and are development environments only.

Before cloning, URL validation, a fixed API host, disabled Git redirects/hooks/helpers,
and refusal to recurse into submodules restrict acquisition. **An OS firewall allowing
only GitHub destinations during acquisition is not implemented.** This does not satisfy
all of section 7.3's network-namespace requirement. Deployment remains localhost-only;
no public-hosting or full sandbox-hardening claim is made. Container termination also
cleans up descendants; native development is not an execution host for research targets.

## User interface and installation

Retain the existing bilingual walkthrough and report iframe. Add URL-based run restoration
and a separately tested SSE/polling controller. Errors with SSE `data` are job failures;
transport errors fall back to polling every three seconds, including through API restarts.

Ship templates, demo copy, sample artifacts, synthetic examples and X-Wing vectors inside
the wheel. A source checkout is no longer required to run the installed app. The API and
worker must share `QUANTA_DB` and `QUANTA_ARTIFACT_ROOT`.
