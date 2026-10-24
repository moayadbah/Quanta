# Measurement protocol, round ten (written before any result of this round)

Written: 2026-10-18. This was before any ruleset change of this round and before any repository of the new set was screened, labelled or scanned.

**Brief.** The team, 2026-10-18: options 1 to 4 of the round-nine follow-up, then one measurement on a new held-out set of 30 repositories. The options are:
1. pyOpenSSL methods on followed objects.
2. Crypto objects passed between functions of one file.
3. Rarer TLS libraries.
4. The assignment false positive.

**Engines.**
- v5 (2026.11.01, shipped).
- v9 (2026.11.05, round nine, unpublished).
- v10 (this round).

**Base.** `Downloads/Quanta-R9-draft/v9-engine.patch` on main ce201a3.

## R10-0. Development data

0.1 H9's errors have been read (`evidence/r9/accuracy-r9.json`), so H9 joins D, H3, H4, H6, H7 and H8 as development data: 170 repositories.

0.2 The inputs for development are:
- The 56 v9 misses on H9 and their causes (DRAFT-R9).
- The two false positives shared by all engines.

0.3 The ten repositories kept by the unused round-nine replacement draw (`evidence/r9/extra/`, positions 694 to 828) were never labelled or scanned. They are excluded from H10 all the same, because they were screened.

## R10-A. Development

A1. Every name comes from the library's documentation and is checked against the installed library. Every change is logged in `evidence/r10/dev-log.jsonl` with its reason and a test.

A2. Gate on every development set, D to H9:
- Each metric's found count is at least v9's.
- False positives are at most v9's.
- Exception: a false positive that is a call the amended codebooks count and the older labels did not is listed, and does not block.

A3. Regression without labels on the 58 old repositories:
- Every removed site is explained.
- Every added site is read.

A4. Performance:
- **Measure:** the full `quanta analyze` over the 21 H4 clones, three alternating runs, median.
- **Gate:** v10 is not slower than v9 by more than 5%.

A5. Scope is the engine only: detection, operations and the ruleset. The website, README, report and models do not change.

**Rule for option 4.**
- **What changes:** a reference that is the value assigned to an attribute of the `ssl` module (monkeypatching, as in `ssl._create_default_https_context = ssl._create_unverified_context`) is no longer a `crypto_call`.
- **Where it goes:** the detection result keeps it in a separate list of TLS configuration warnings.
- **What is left to the team:** showing that list in the product, because that is a product change.

## R10-B. Codebook (applies to H10; written before any H10 label)

The round-nine codebook (`evidence/r9/CODEBOOK-R9.md`) applies, with two clarifications. Both make explicit how the round-nine annotators labelled such calls where H9 had them (`evidence/r9/labels`). The round-nine codebook named neither case.

**B2j. TLS connections.**
- **Units (A, `tls`):** calls that configure a TLS context or a TLS connection object, or run its handshake, are units. This holds in any library, the standard library included. Examples:
  - pyOpenSSL's `set_options`, `set_verify`, `set_cipher_list`, `use_certificate_chain_file`, `use_privatekey_file`, `set_passwd_cb`, `set_alpn_protos`, `set_tlsext_host_name`, `set_connect_state`.
  - `do_handshake`, `handshakeServer` and `handshakeClientCert`.
- **Not units:** reading, writing and closing (`recv`, `send`, `read`, `write`, `close`, `shutdown`).

**B2k. Event loops.** An asyncio event loop's `start_tls(...)` is a unit (B, `tls`). So are `create_connection(...)`, `create_server(...)` and `create_unix_connection(...)` when they pass a TLS context (`ssl=ctx`, `ssl=True`). This is the B2g rule applied to the event loop.

## R10-C. A new held-out set (H10)

C1. **Frame and order:** as PROTOCOL-R8 C1, continuing at position 829. That is the first position no earlier round screened, the round-nine replacement draw included.

C2. **Exclusions:** as R8-C2, plus every repository screened in round nine, the replacement draw included.

C3. **Strata, draw and quotas:** as R8-C3, with seed `"20261020:" + owner/name`: 20 P and 10 G.

C4. **Size rule:** as R8-C4. If H10 has fewer than 120 units or fewer than 40 PK+TLS units, add 5 P, up to 35 P.

C5. **Labels:**
- Labels come from separate agents that see only the round-ten codebook and the drawn files.
- They are frozen with a SHA-256 manifest before any engine runs on H10.
- The v10 source is frozen (SHA-256) before any H10 label is read.
- H10 annotator reports are not used for development.
- Repositories an annotator refuses follow the round-nine rule (DEVIATIONS-R9 1): a second attempt by a single-repository annotator with a prompt that states the defensive purpose, then replacement in frame order.

## R10-D. Measurement

D1. v5, v9 and v10 each run once on H10. Matching and metrics are as R6-D1 and R6-D2, pooled and per stratum.

D2. **Decision rules, fixed now:**
- **Recall:** v10's recall on A+B exceeds v9's, and so does its PK+TLS recall on A+B.
- **Precision:** v10 has no false positive that v9 lacks, and the Wilson lower bound of v10's precision is at least 0.95.
- **Speed (R10-A4):** v10 is not slower than v9 by more than 5%.

D3. **Reporting:**
- Every miss and false positive of each engine is listed by file and line.
- Nothing on the website or README changes in this round.
- The repository is not modified.
