# Quanta

Understand the cryptography in a Python repository, review focused improvements, and
open a draft GitHub pull request. Quanta finds cryptographic call sites, maps their
dependencies, and explains its architecture score with file and line references.
Repository code is parsed, never imported, installed or executed.

The product is bilingual in English and Arabic, with a responsive interface, private
scan history, an interactive sample, a diff review, and explicit compatibility checks.
The design uses warm neutrals, muted green, and an original geometric motif inspired
by Saudi Sadu weaving.

## Product scope

| Capability | Behavior |
|---|---|
| GitHub sign-in | OAuth with PKCE, single-use state, encrypted server-side tokens, HttpOnly sessions |
| Public repository scans | Pinned commit, bounded traversal, deterministic analysis, private results |
| Reviewable changes | MD5/SHA-1 to SHA-256 proposals for supported `hashlib` and `cryptography` calls |
| Diff review | Only selected call sites change; original imports, comments and line endings are preserved |
| Draft pull requests | Dedicated branch or user fork, original-source verification, persistent retry handling |
| Free allowance | 3 new scans per account per UTC day; 50 shared new scans per calendar month |
| Hosting | Vercel FastAPI + disposable Sandbox microVMs + free PostgreSQL storage |
| Sample | Working analysis and diff review without sign-in; never creates a real PR |

Hash upgrades change digest values and lengths. Review stored values, protocols,
signatures, fixtures and downstream consumers before merging. Syntax validation does
not establish behavior compatibility, and repository tests are not run by the service.
Key, certificate and protocol migrations require manual engineering. The agility score
measures architectural flexibility; it is not a security grade or a quantum-readiness
certification. Dynamic Python behavior may not be resolved statically.

The original benchmark, annotations and comparison-engine research plan is optional
historical work. It does **not** gate the product release. See
[ADR-026](docs/adr/ADR-026-published-product.md).

## Run locally

```bash
docker compose up --build
```

Open **http://localhost:8000**. The local app supports unsigned development scans by
default; the Vercel entrypoint always requires sign-in. The legacy educational
walkthrough remains available at `/guide.html`.

Without Docker, install Python 3.12 and Git, then:

```bash
uv sync --locked --extra dev
uv run quanta serve
```

Run `uv run quanta worker --id w1` in a second terminal. Both use `~/.quanta` by default.
Set the same `QUANTA_DB`, `QUANTA_ARTIFACT_ROOT` and `QUANTA_SCRATCH_ROOT` for both when
using another location. Environment values override TOML defaults. To exercise OAuth
locally, use a separate GitHub OAuth application and configure the variables in
`.env.example` in the process environment. Configuration is not read from `.env`
automatically.

Compose gives the worker an internal network and a GitHub-only CONNECT proxy. Its
non-root processes use read-only mounts, dropped capabilities, resource limits,
watchdogs and a post-clone seccomp network cutoff. Native development commands do not
provide the complete Docker network boundary.

## Publish on Vercel

Follow [the deployment guide](docs/DEPLOYMENT.md). The code includes a FastAPI entrypoint,
locked dependencies, hosting limits, the cloud runner, and a trusted snapshot builder.
Use Vercel **Hobby** and a **free** PostgreSQL project. Do not select a paid plan.

A ChatGPT GitHub/Vercel connection is separate from the application's own OAuth
registration and runtime database. The deployed application needs those configured
before live sign-in and scanning can work. Without them, the public site offers the
sample and explains that live scanning is unavailable; it does not silently run
anonymous scans or pretend a live analysis succeeded.

## CLI and artifacts

```bash
uv run quanta analyze https://github.com/pallets/click --out out
uv run quanta analyze path/to/repository --out out --trace
uv run quanta analyze path/to/repository --cbom path/to/cbom.json --out out --json
```

Outputs are `cdg.json`, `score.json`, `meta.json`, `report.html`, and `fixes.json`.
The HTML works offline. `fixes.json` contains bounded original source files needed to
apply selected proposals, so keep it with the private analysis artifacts. Hosted results
expire after seven days. A local path uses a zero commit SHA and cannot be published as
a live repository PR. Optional CycloneDX 1.6 evidence carries source provenance and
reports unusable locations explicitly.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/auth/login`, `/auth/callback`, `/auth/session` | GitHub sign-in and current session |
| POST | `/auth/logout` | End the current session |
| GET | `/api/v1/workspace` | Private history, usage and availability |
| POST | `/api/v1/analyses` | Resolve and enqueue; 200 on reuse, 201 for new work |
| POST | `/api/v1/analyses/{id}/run` | Run queued hosted work; durable claim prevents duplicate scans |
| GET | `/api/v1/analyses/{id}` | Durable status and progress |
| GET | `/api/v1/analyses/{id}/score`, `/meta`, `/cdg`, `/report` | Private results |
| GET | `/api/v1/analyses/{id}/fixes` | Supported change proposals, without retained full source |
| POST | `/api/v1/analyses/{id}/review` | Generate the selected diff and a content digest |
| POST | `/api/v1/analyses/{id}/pull-request` | Publish exactly that reviewed selection as a draft PR |
| GET | `/api/v1/sample` | Stateless working example |

Authenticated mutations require the canonical `Origin` and the session's `X-CSRF-Token`.
The browser starts hosted jobs and polls their durable status; a page reload can resume a
queued scan. A lost running invocation expires and is never retried against the free
compute budget automatically. Local workers run queued jobs independently.

## Validation

```bash
uv sync --locked --extra dev --extra research
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
node --check src/quanta/web/static/product.mjs
node --test tests/frontend.test.mjs
uv build --wheel
```

CI also exercises a real disposable PostgreSQL database, installed-wheel assets,
Docker isolation and a live public-repository scan. Tests cover OAuth state, account
isolation, CSRF, concurrent quotas, source-preserving changes, stale branches, fork
retries, duplicate PR prevention, cloud lifecycle and artifact expiry. Live OAuth and
Vercel infrastructure still require account configuration and a deployment smoke test.
