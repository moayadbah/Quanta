# Quanta

**Cryptographic agility measurement and assisted post-quantum migration for Python repositories.**

Quanta ingests a public Python repository, builds a **Cryptographic Dependency Graph (CDG)**,
and computes an **Agility Score (0–100)** — a defensible per-repository estimate of how hard
it would be to replace a cryptographic algorithm in that codebase. Every deduction in the
score cites a `file:line`.

Post-quantum migration is not blocked by algorithm availability; NIST finalised ML-KEM and
ML-DSA in 2024 and `pyca/cryptography` ships them today. What is unsolved is the engineering
cost of the swap inside an existing codebase. Quanta measures that cost from the source.

## The one thing to know about the architecture

**The analysis tier performs static analysis only. It never executes target code.**

`pip install` runs arbitrary build-backend code before any test does, and Python cannot be
sandboxed in-process. So the system splits into two planes with a hard trust boundary:

| | Analysis Plane | Research Plane |
|---|---|---|
| Input trust | Untrusted (any public repo) | Vetted (hand-selected forks) |
| Executes target code? | **Never** | Yes, in hardened containers |
| Credentials present? | None | PAT, on the PR step only |

The dangerous half of the pipeline is never deployed. See `docs/adr/`.

## Status

The §11.4 first milestone is **reached**:

> `quanta analyze <public python repo URL>` produces `cdg.json`, `score.json` and a
> `report.html` that opens offline — with the entire `tests/security/` suite green.

363 tests pass (270 of them security), `ruff` and `mypy --strict` are clean. Verified
against live repositories: `pallets/click` scores 100 (it contains no cryptography, which
is the correct answer), `jpadilla/pyjwt` scores 13.8 across 27 detected sites. Three
independent clones produce byte-identical `cdg.json` and `score.json`.

| Definition of Done | State |
|---|---|
| DoD-C1 ingestion | ✅ security suite green; scratch removed on success, failure and timeout |
| DoD-C2 detection | ⚠️ precision/recall reported separately against **synthetic** fixtures; the real figure needs the frozen benchmark (Phase 1) |
| DoD-C3 CDG | ✅ round-trips through `node_link_graph`; every `call` edge `confidence: "low"`; byte-identical across 3 runs |
| DoD-C4 score | ✅ weights from the `weights-v1` tag; every deduction carries ≥1 `file:line`. Sensitivity and collinearity belong to the stats phase |
| DoD-C5 report | ✅ opens from `file://` with no network; CSP defined; hostile filenames render escaped; CDG SVG inline |
| DoD-V2 X-Wing shim | ✅ 1000-example Hypothesis property, plus known-answer tests against draft-10 Appendix C |

Engines (E0/E1/E2), the verification harness, the benchmark corpus, the statistics layer
and the web tier are build-order steps 8–12 and are **not** built yet. `--cbom` (PROC-06)
refuses rather than silently ignoring the flag.

### Deviations from the specification

Three, each forced by a verified fact and recorded in `docs/adr/`:

- **ADR-017** — `cryptography` pinned `>=48,<49`. Upstream dropped x86_64 macOS wheels at
  49.0.0; 48.0.1 ships ML-KEM via OpenSSL 4.0.1.
- **ADR-018** — deterministic built-in SVG renderer instead of Graphviz. No system binary,
  and layout stability is required by NFR-03.
- **ADR-019** — the X-Wing combiner appends `XWingLabel` **last**, per draft-10 §5.3. §3.9
  of the technical documentation places it first; the published test vectors show that
  order is wrong. §3.9 should be corrected in the next revision.

## Quick start

```bash
uv sync --extra dev
```

Run the analyzer against any public Python repository:

```bash
uv run quanta analyze https://github.com/pallets/click --out ./out
```

This writes `cdg.json`, `score.json`, `meta.json` and a self-contained `report.html` into
`./out`. The report opens directly from the filesystem with no server and no network.

Tests:

```bash
uv run pytest tests/unit tests/security -v
```

`tests/security/` encodes the SSRF, path-traversal, resource-exhaustion and injection
controls from §7.3. Those tests are **acceptance criteria, not extras** — a change that
breaks one of them is a defect regardless of what else it improves.

## What Quanta is not

- **Not a migration-cost estimator.** It measures *source-edit difficulty*. Real cost is
  dominated by certificates, protocols, hardware and compliance — all out of scope.
- **Not a cryptographic security review.** Verification proves functional correctness, not
  cryptographic soundness. That limitation is a stated result, not an apology.
- **Not a code execution service.** See above.
- **Not multi-language.** Python only.

## Requirements

- Python 3.12 (`uv python pin 3.12`)
- `git` on PATH
- No Graphviz required — the CDG SVG is emitted by a deterministic built-in renderer
  (`docs/adr/ADR-018-deterministic-svg.md`)

## License

MIT. Analysed repositories retain their own licenses; Quanta redistributes no third-party
source — clones are deleted unconditionally at job end (INGEST-09).
