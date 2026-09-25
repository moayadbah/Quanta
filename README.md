# Quanta

Quanta tells you how ready a Python codebase is for post-quantum cryptography. Point it at a
public GitHub repository and it answers three questions, each with a file and line:

1. **What cryptography is in the code.** Every cryptographic call, found by parsing the
   source. The code is never imported, installed or run.
2. **What to change.** Every finding that needs action gets exactly one entry: an automatic
   patch where the change is safe, a guided migration with working example code where it is
   not, or a refusal with its reason. Nothing is skipped silently.
3. **How far it is from the deadlines.** Each finding is held against the published
   post-quantum and deprecation milestones of NIST, NSA CNSA 2.0, the Saudi NCA, the EU,
   the UK NCSC and US Executive Order 14412, each linked to its source.

Live at **https://quanta-gilt-mu.vercel.app**. Sign in with GitHub to scan any public
repository (three scans a day), or open the recorded sample without an account. You can
review the selected patches as one diff and open them as a draft pull request, and export
the readiness report as a PDF.

## How readiness works

Only shipped code counts. Tests, examples and docs are listed separately and never change
the verdict. Each cryptographic call site in shipped code is classed by what a quantum
computer, or today's cryptanalysis, does to it:

| Status | Meaning | Examples |
|---|---|---|
| Quantum-vulnerable | Broken by a large quantum computer | RSA, ECDSA, EdDSA, DH, ECDH, X25519 |
| Weak | Already unsafe or disallowed today | MD5, SHA-1, Triple DES, DES, RC4, ECB mode |
| Needs review | Asymmetric call whose algorithm cannot be read statically, so assumed classical | `load_pem_private_key(...)` |
| Post-quantum | ML-KEM, ML-DSA, SLH-DSA, or a hybrid such as X25519MLKEM768 | |
| No action | Current symmetric cryptography and hashes | AES-GCM, SHA-256, HMAC |

The sites are then matched to the milestones in [`config/standards.json`](config/standards.json).
Every milestone names its source, and every date was checked against its primary document
and at least one independent source on 25 September 2026:

| Framework | Rule Quanta applies | Source |
|---|---|---|
| NIST | MD5 not approved (in force); Triple DES encryption disallowed after 2023; SHA-1 retired by 31 Dec 2030; RSA and finite-field DH at 112-bit strength deprecated after 2030; all quantum-vulnerable signatures and key establishment disallowed after 2035 | [SP 800-131A Rev. 2](https://doi.org/10.6028/NIST.SP.800-131Ar2), [SHA-1 retirement](https://csrc.nist.gov/news/2022/nist-transitioning-away-from-sha-1-for-all-apps), [IR 8547 ipd](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf) (draft) |
| NSA CNSA 2.0 | Software and firmware signing exclusively CNSA 2.0 by 2030; web and cloud by 2033; custom applications updated or replaced by 2033 (US national security systems) | [CNSA 2.0 advisory](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF) |
| Saudi NCA | Post-quantum algorithms only in hybrid with an approved classical one (clause 2-5-5-1); no year set | [NCS-2:2025 consultation draft](https://istitlaa.scbc.gov.sa/en/security/nca/ncs/Documents/NCS-2-en.pdf) |
| EU | High-risk use cases by 31 Dec 2030; medium-risk by 31 Dec 2035 | [Coordinated Implementation Roadmap](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography) |
| UK NCSC | Discovery by 2028; highest-priority migration by 2031; everything by 2035 | [PQC migration timelines](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) |
| US | Federal high-value systems: post-quantum key establishment by 31 Dec 2030, signatures by 31 Dec 2031 | [Executive Order 14412](https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/) |

The verdict is **At risk**, **In transition** (some post-quantum already), **Ready**, or
**No cryptography found**. A repository that *is* the cryptography, such as python-ecdsa,
is recognised and said so plainly: its users can only migrate once it offers a
post-quantum scheme beside the classical one, and the guided migration shows how.

Readiness is not a security review and not a migration cost estimate. Certificates,
protocols, hardware and third-party services are outside what a source scan can see.

## Measured, with sources

| Figure | Value | How it was measured | Evidence |
|---|---|---|---|
| Recall on a held-out set | 94.6% (70 of 74 labelled calls; 95% CI 86.9 to 97.9) | 20 repositories drawn by a pre-registered rule, labelled line by line before the rules were frozen, scored once | [`evidence/PROTOCOL-R4.md`](evidence/PROTOCOL-R4.md), [`evidence/r4/accuracy-release-r5.json`](evidence/r4/accuracy-release-r5.json) |
| Precision on the same set | 100% (71 of 71; lower bound 94.9) | Every reported call matched against the labels | same |
| Known weak spot | 4 of 8 public-key and TLS calls hidden behind other libraries | Same set | same |
| Reading avoided | 77 hours in the median repository | Lines of shipped code at 200 lines an hour, the fastest pace at which review stays effective ([Kemerer and Paulk, 2009](https://sites.pitt.edu/~ckemerer/PSP_Data.pdf)) | [`evidence/r4/TIME-COST-METHOD.md`](evidence/r4/TIME-COST-METHOD.md), [`evidence/r4/time-cost.json`](evidence/r4/time-cost.json) |
| Engineering time saved | $5,007 per median repository | Those hours at the US software developer wage ([BLS, May 2025](https://www.bls.gov/ooh/computer-and-information-technology/software-developers.htm)), no overhead | same |
| Already past a deadline | 80 calls across 60 public repositories | Each call mapped to the milestones above | [`evidence/r4/time-cost.json`](evidence/r4/time-cost.json) |
| Scan time | 15.3 s for the median repository | Wall clock, one laptop, repository already on disk | same |

The single annotator was the model that built the tool and was not blind to its design; the
protocol states this as a limit.

## Proven on Python, built for more languages

Quanta models cryptography as algorithms, call sites, data flow and deadlines, and none of
those depend on the language. Python is where it is measured today. The parser front end
(LibCST) is the only Python-specific layer; the rules, readiness, proposals and report are
shared.

## Run locally

With Python 3.12, Git and [uv](https://docs.astral.sh/uv/):

```bash
uv run quanta up
```

Open http://127.0.0.1:8000. `quanta up` starts the web app and a worker together and stops
both on Ctrl+C. Locally no sign-in is needed: paste a public repository or open the sample.
Data lives in `~/.quanta`. For the full network boundary (GitHub-only egress proxy, seccomp
cutoff after clone) use `docker compose up --build`.

## CLI

```bash
uv run quanta analyze https://github.com/tlsfuzzer/python-ecdsa --out out --pdf
uv run quanta analyze path/to/source --out out --trace
```

Writes `readiness.json`, `findings.json`, `fixes.json` (patches, guided migrations and
refusals), `score.json`, `cdg.json`, `meta.json`, `report.html` and, with `--pdf`,
`report.pdf`. Verification stays in the CLI: `uv run quanta verify PATH` runs a project's
own tests before and after the selected patches in a sealed Docker container, and
`uv run quanta trace PATH` reports how many of the cryptographic lines those tests execute.
The hosted service never runs repository code.

The agility score in `score.json` measures how easy the algorithms are to change (call
sites, isolation, whether the algorithm is a setting, spread). It is not a security grade.

## Editing the words

Every visible string, in English and Arabic, is in [`content/site.json`](content/site.json),
including the report and the PDF. Keep anything in curly braces such as `{n}` as it is, then
run `uv run pytest tests/unit/test_site_content.py`.

## Hosting

`main` deploys to Vercel. The function (`api/index.py`) requires GitHub sign-in, stores data
in a free Supabase Postgres database (tables are created at startup), and runs each live scan
in a disposable Vercel Sandbox microVM with network access limited to GitHub. Configure the
variables in [`.env.example`](.env.example) in Vercel; the full steps are in
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). The sample is recorded with
`uv run python scripts/record_sample.py` and replayed from `demo/sample/`.

## Validation

```bash
uv sync --locked --extra dev
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest tests/unit tests/security
node --test tests/frontend.test.mjs
```
