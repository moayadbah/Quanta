# Measurement protocol, round eleven (written before any result of this round)

**Written:** 2026-10-19, before any ruleset change of this round and before any repository of the new set was screened, labelled or scanned. Author: Claude.

**Brief.** The team, 2026-10-19, asked for the final version, with:
- Options 1 to 4 of the round-ten review (option 5 if time allows):
  1. Precision fixes.
  2. Coverage-driven development.
  3. TLS options of networking clients.
  4. Small names.
  5. Cross-file tracking.
- H11 with 60 repositories.
- Double labelling on 10 of them.
- Revised decision rules written before the measurement.

**Engines:**
- v5 (2026.11.01, shipped).
- v9 (2026.11.05).
- v10 (2026.11.06).
- v11 (this round).

**Base:** `Downloads/Quanta-R10-draft/v10-engine.patch` on main ce201a3.

## R11-0. Development data

0.1 H10's errors have been read (`evidence/r10/accuracy-r10.json`). H10 therefore joins D, H3, H4 and H6 to H9 as development data: 200 repositories.

0.2 Coverage-driven development (option 2) reads only repositories that are not in H11:
- The clones already made by the round-eight to round-ten screenings (`Downloads/Quanta-R8-draft/clones-h8`, `Quanta-R9-draft/clones-h9`, `Quanta-R10-draft/clones-h10`).
- Every one of them is excluded from H11 by R11-C2.
- **Method:** the engine's own record of crypto-library names it does not know (`unmatched_names`) is ranked by the number of repositories that use each name. A text scan ranks calls that pass TLS keywords (`ssl_context=`, `cert_reqs=`, `ca_certs=`, `ssl=`, `tls=`, `verify=`, `ssl_options=`).
- **Use:** each name added is checked against the library's documentation and the installed library (R11-A1). No labels are made or read for these repositories.

## R11-A. Development

A1. Every name comes from the library's documentation and is checked against the installed library. Every change is logged in `evidence/r11/dev-log.jsonl` with its reason and a test.

A2. **Gate on every development set, D to H10:**
- Each metric's found count is at least v10's.
- False positives are at most v10's.
- **Exceptions (listed, not blocking):**
  - A false positive that is a call the amended codebooks count and the older labels did not.
  - A unit of the older labels that the round-eleven clarification B2l no longer counts.

A3. **Regression without labels** on the 58 old repositories:
- Every removed site is explained.
- Every added site is read.

A4. **Performance:**
- **Measured on:** the full `quanta analyze` over the 21 H4 clones.
- **Method:** three alternating runs, median.
- **Gate:** v11 is not slower than v10 by more than 5%.

A5. **Scope is the engine only:** detection, operations and the ruleset. The website, README, report and models do not change.

## R11-B. Codebook (applies to H11; written before any H11 label)

The round-ten codebook (`evidence/r10/CODEBOOK-R10.md`) applies, with one clarification. Round-seven and round-ten annotators split on these calls: H7 counted `pad` and `unpad`; H10 did not count six such calls.

- **B2l. Helpers that only prepare data or parameters for another call are not units.** This covers:
  - Block-padding helpers (`Crypto.Util.Padding.pad`, `unpad`).
  - The `padder()` and `unpadder()` of `cryptography`'s `padding.PKCS7(...)`.
  - The encryption choice passed to a key serialisation call (`serialization.BestAvailableEncryption(...)`, `NoEncryption()`). These are parameter objects under B2f.

  The cipher call and the serialisation call they feed are the units.

## R11-C. A new held-out set (H11)

C1. **Frame and order:** as PROTOCOL-R8 C1, continuing at position 1083. That is the first position no earlier round screened.

C2. **Exclusions:** as R10-C2, plus every repository screened in round ten.

C3. **Strata, draw and quotas:**
- As R8-C3, with seed `"20261021:" + owner/name`.
- Quotas: 40 P and 20 G.

C4. **Size rule:** if H11 has fewer than 240 units or fewer than 80 PK+TLS units, add 5 P in frame order and label them, up to 50 P.

C5. **Labels:**
- **Who labels:** separate agents that see only the round-eleven codebook and the drawn files. Every annotator gets the prompt that states the defensive purpose. Each annotator's final message gives unit counts only.
- **Freezing:** labels are frozen with a SHA-256 manifest before any engine runs on H11. The v11 source is frozen (SHA-256) before any H11 label is written.
- **Refusals:** a repository an annotator refuses follows DEVIATIONS-R9 1.

C6. **Double labelling.**
- **Which repositories:** 10 repositories (7 P, 3 G) are drawn now. Rule: `random.Random("20261021:double").sample(sorted(names), k)` within each stratum, after the draw.
- **Who labels them:** each gets a second, independent annotator who does not see the first labels.
- **Labels used for scoring:** the first annotator's labels, always. This is fixed now, so no label is chosen after seeing the engines.
- **Agreement:** two units agree when they are in the same file and their line ranges overlap (one-to-one, greedy in line order). Reported measures:
  - Agreement F1 = 2·matched / (units₁ + units₂).
  - The share of matched units with the same kind.
- **Thresholds:** F1 ≥ 0.85 is reported as good agreement. Below that, the H11 figures are reported with that limitation. Agreement is computed after both label sets are frozen and before the engines run.

## R11-D. Measurement

D1. v5, v9, v10 and v11 each run once on H11. Matching and metrics are as R6-D1 and R6-D2, pooled and per stratum. Engine snapshots carry `config/`, `templates/` and `content/` beside `src` (DEVIATIONS-R10 3).

D2. **Decision rules, revised and fixed now.** Round ten's "must exceed" rule fails for an engine whose remaining gains are spread thinly, so the primary rule is now non-inferiority with a pre-set margin.
- **Recall, primary:**
  - v11's A+B recall on H11 is not below v10's.
  - v11's A+B recall is not below v9's.
  - The same two conditions hold for PK+TLS recall on A+B.
  - These are found counts on the same units.
- **Recall, improvement:** v11 is called "better than v10" only if it finds more A+B units than v10. The paired counts are reported with an exact two-sided McNemar test:
  - Units v11 finds that v10 misses, and the reverse.
  - The test is reported, not used as a gate.
- **Precision:**
  - v11 has no false positive that v10 lacks.
  - The Wilson lower bound of v11's precision is at least 0.95.
- **Speed (R11-A4):** v11 is not slower than v10 by more than 5%.

D3. **Independent pooled figure.** Each engine is also reported on every held-out set it had not seen when it was frozen:
- v9 on H9 + H10 + H11.
- v10 on H10 + H11.
- v11 on H11.
- The pooled figures are sums of found and total counts, with Wilson intervals.

D4. **Reporting:**
- Recall is reported separately for quantum-vulnerable kinds (PK+TLS: `public_key`, `key_handling`, `tls`) and for the rest.
- Every miss and false positive of each engine is listed by file and line.
- Nothing on the website or README changes in this round.
- The repository is not modified.
