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

## Isolation boundary

Linux child processes have resource limits, a parent-death signal, and a libseccomp filter
that rejects new sockets, connections on existing sockets, sends and io_uring after
cloning. Compose requires these controls and fails closed if installation fails.
`libseccomp2` is a system dependency required by NFR-04 and section 7.3; no additional
Python dependency is introduced. Native macOS and Windows have the process watchdog but
cannot provide the Linux controls and are development environments only.

Before cloning, the worker joins only an internally isolated Docker network. It cannot
open direct external sockets. Docker resolves the internal proxy service name, while the
worker's external DNS resolver is disabled. The separate Squid service has an external
network and allows CONNECT only to the exact `github.com` and `api.github.com` names on
port 443. Literal IPs cannot acquire an allowlist match through reverse DNS, and resolved
private destinations are denied. There is no TLS interception; Git verifies GitHub's
certificate end to end. No proxy port is published and neither the worker nor the proxy
gets elevated network capabilities. Squid is a system dependency justified by section
7.3's acquisition boundary; a hand-written proxy would add avoidable protocol risk.

The deployment supplies `QUANTA_INGEST__PROXY_URL` explicitly to Git. Ambient proxy
variables and `NO_PROXY` are discarded with credentials. Application URL validation,
disabled redirects/hooks/helpers and refusal to recurse into submodules remain in place.
The API resolves metadata through the fixed GitHub API host; it never parses target code.

CI executes `scripts/check_worker_egress.py` inside the worker: direct IPv4/IPv6 sockets
and external DNS must fail, forbidden proxy destinations must return 403, and a GitHub
TLS tunnel must succeed. The live-clone test then checks the real acquisition path.
Native development does not provide this network topology. Deployment remains
localhost-only; target-code execution and public hosting are not enabled.

References: [Compose internal networks](https://docs.docker.com/reference/compose-file/networks/#internal),
[Squid ACLs](https://www.squid-cache.org/Doc/config/acl/) and
[Git proxy configuration](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpproxy).

## User interface and installation

Retain the existing bilingual walkthrough and report iframe. Add URL-based run restoration
and a separately tested SSE/polling controller. Errors with SSE `data` are job failures;
transport errors fall back to polling every three seconds, including through API restarts.

Ship templates, demo copy, sample artifacts, synthetic examples and X-Wing vectors inside
the wheel. A source checkout is no longer required to run the installed app. The API and
worker must share `QUANTA_DB` and `QUANTA_ARTIFACT_ROOT`.
