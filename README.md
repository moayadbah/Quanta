# Quanta

Cryptographic agility analysis for Python repositories. Quanta finds cryptographic call
sites, builds a dependency graph, and reports a 0–100 source-edit agility score with
`file:line` evidence for each deduction. Analysis parses source without importing it,
installing its dependencies, or running its code.

## Run the application

```bash
docker compose up --build
```

Open **http://localhost:8000**. The bilingual English/Arabic interface includes the guided
walkthrough, offline example replays, and a public GitHub repository analyzer. Reports
open in a sandboxed iframe and download as self-contained HTML. Source snapshots are
removed after analysis; completed artifacts expire after seven days.

The API and worker are separate processes. SQLite persists jobs, events and cache entries
across API restarts. Jobs have bounded attempts, lease recovery, a wall-clock watchdog,
and a shared concurrency cap. The browser restores a run after refresh and falls back to
polling when streaming fails. Docker binds the service to localhost.

For development without Docker, use Python 3.12 and Git. Install once:

```bash
uv sync --locked --extra dev --extra research
```

Run these in **two terminals** from the repository:

```bash
uv run quanta serve
```

```bash
uv run quanta worker --id w1
```

Both use `~/.quanta` by default. To choose another location, set the same `QUANTA_DB`,
`QUANTA_ARTIFACT_ROOT` and `QUANTA_SCRATCH_ROOT` in both terminals. Nested settings use
names such as `QUANTA_INGEST__MAX_FILES=10000`; environment settings override defaults.
Native macOS/Windows development does not provide Linux sandbox controls.

## Analyze from the command line

```bash
uv run quanta analyze https://github.com/pallets/click --out out
uv run quanta analyze tests/fixtures/repos/hardcoded_crypto --out out --trace
uv run quanta analyze path/to/repository --cbom path/to/cbom.json --out out --json
```

Each analysis produces `cdg.json`, `score.json`, `meta.json` and `report.html`. The HTML
opens offline without a server. URL analyses are pinned to a resolved commit; a moving
head causes `SHA_MISMATCH`. Local working-copy analyses use a zero SHA and are explicitly
not pinned results. Optional CycloneDX 1.6 assets with source locations are merged and
marked `source: cbom`; unusable locations are reported. A CBOM digest participates in
provenance so different inputs cannot masquerade as the same analysis.

## What is complete and what remains

| Component | Current state |
|---|---|
| Static analyzer, dependency graph, cited score, offline report | Implemented and tested; real-corpus detection precision/recall remain unmeasured |
| CycloneDX input | Located 1.6 occurrences supported; unlocated assets reported |
| Durable API, worker, events, cache, retention | Implemented with restart, race, retry and watchdog tests |
| Bilingual application and offline demos | Existing walkthrough retained; reconnection and reload recovery added |
| Wheel and local container packaging | Included; installed-wheel assets verified |
| X-Wing primitive shim | Existing draft-10 vectors and 1,000-example round-trip property pass |
| Benchmark selection, worksheets, annotation import, agreement, freeze | Tooling implemented; the actual 12-repository independent annotation is pending |
| McNemar, repository bootstrap, sensitivity, collinearity | Implemented; demo outputs and synthetic test results are not research findings |
| E0/E1/E2, P0/P1 rewriting, target verification, fork PR automation | Not implemented: the technical document requires the labelled benchmark to be frozen first |

**This revision completes the durable analysis application, not the full research MVP.**
Follow [the benchmark workflow](docs/research/WORKFLOW.md) to supply independent annotations
and unlock the migration phase. No completed corpus, independent reviews, migration
success rates, DOI or publication results are fabricated.

The original score weights remain unchanged and are pinned to commit
`6f392e5b5fb12a39a19f1443e20ed7aeb76c241f`. Publishing the `weights-v1` tag is still pending;
the benchmark workflow gives the exact command. Sensitivity and factor
collinearity reports for the three existing examples are in
[docs/research/demo-statistics](docs/research/demo-statistics); they are clearly labelled
as demonstration output and do not justify a corpus-level conclusion.

## Validation

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
node --test tests/frontend.test.mjs
uv build --wheel
```

CI also builds and starts the Compose service, checks its worker and example replay,
tests the worker's actual acquisition network boundary, and submits a public repository
twice to exercise pinned ingestion and cache reuse.
`tests/security` covers URL rejection before network access, traversal, symlinks, special
files, budgets, forbidden execution paths, report escaping, artifact confinement, and
Linux post-clone network isolation. Database tests cover restart persistence, competing
claims, expired leases, old-attempt fencing, retries, publication and retention.

## Scope and isolation

The score measures source-edit difficulty, not total migration cost or cryptographic
security. Static Python analysis can miss dynamic dispatch and other unresolved behavior.
A result without detected cryptography does not prove its absence. Target tests and
migration execution are not exposed through the web API.

Compose runs as non-root with dropped capabilities, a read-only filesystem and bounded,
non-executable scratch space. The worker's internal Docker network has no direct external
route. Its only acquisition path is a separate CONNECT proxy allowing the exact names
`github.com` and `api.github.com` on port 443. External DNS forwarding is disabled in the
worker. Git verifies GitHub's TLS certificate through the tunnel; a Linux seccomp filter
cuts network access after cloning. Redirects, hooks and credential helpers are disabled.
These controls depend on the supplied Compose topology and are not provided by native
development commands. Public hosting and hostile target-code execution remain out of scope.
See [ADR-023](docs/adr/ADR-023-durable-local-analysis.md).

The existing ADRs preserve the no-build frontend, deterministic SVG renderer and corrected
X-Wing combiner order. [ADR-024](docs/adr/ADR-024-corpus-query-and-annotation-gate.md)
records the corrected GitHub query and research gate; [ADR-025](docs/adr/ADR-025-cbom-and-provenance.md)
documents CBOM support and its limits. No extra Python dependencies were added.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/analyses` | Resolve and enqueue a public GitHub URL; return 200 on reuse, 201 for new work |
| GET | `/api/v1/analyses/{id}` | Durable status and progress |
| GET | `/api/v1/analyses/{id}/events` | SSE with `Last-Event-ID` replay |
| GET | `/api/v1/analyses/{id}/score` | Canonical score JSON |
| GET | `/api/v1/analyses/{id}/report` | Sandboxed, downloadable HTML |
| GET | `/api/v1/healthz` | Queue depth and worker heartbeat age |

Additional read endpoints expose graph, metadata, trace, examples and walkthrough content.
Errors use `application/problem+json` with a stable `error_code` and correlation ID.
The machine-readable schema is at `/api/openapi.json`.

## License

MIT. Analyzed repositories retain their own licenses. Research publication must contain
labels and commit references rather than copies of third-party source.
