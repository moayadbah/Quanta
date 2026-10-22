# Measurement protocol, round nine (written before any result of this round)

Written: 2026-10-17, before any ruleset change of this round and before any repository of the
new set was screened, labelled or scanned. Author: Claude.
Brief (the team, 2026-10-17): the ninth and last version; raise the engine's accuracy and
performance with every idea that helps.
Engines: v5 (2026.11.01, shipped), v8 (2026.11.04, round eight, unpublished), v9 (this round).
Base: `Downloads/Quanta-R8-draft/v8-engine.patch` on main ce201a3.

## R9-0. Development data

0.1 H8's errors have been read (evidence/r8/accuracy-r8.json), so H8 joins D, H3, H4, H6 and H7
as development data: 140 repositories.
0.2 Inputs for development: the 57 v8 misses on H8 and their causes (accuracy-r8.json,
`v8_misses_by_cause_detail`), and the four false positives shared by all engines.

## R9-A. Development

A1. Every name comes from the library's documentation and is checked against the installed
library. Every change is logged in `evidence/r9/dev-log.jsonl` with its reason and a test.
A2. Gate on every development set: each metric's found count is at least v8's, and false
positives at most v8's; a false positive that is a call the amended codebooks count and the
older labels did not is listed and does not block.
A3. Regression without labels on the 58 old repositories: every removed site explained, every
added site read.
A4. Performance: the full `quanta analyze` over the 21 H4 clones, three alternating runs, median.
Gate: v9 not slower than v8 by more than 5%. A speed change that replaces a metadata provider
must give the same answer as the provider on every node of every development file (checked by a
script before the change is kept).

## R9-B. Codebook (applies to H9; written before any H9 label)

The round-eight codebook (`evidence/r8/CODEBOOK-R8.md`, R6-B1 to B3 with B2a to B2e), plus:
 - B2f. Parameter objects are not units of their own: instances of a padding scheme
   (`padding.OAEP(...)`, `padding.PSS(...)`, `padding.MGF1(...)`), of a hash algorithm or cipher
   algorithm or mode passed as a parameter (`hashes.SHA256()` given to another call,
   `algorithms.AES(k)` and `modes.CBC(iv)` given to `Cipher`), and backends
   (`default_backend()`). The call that uses them is the unit. A hash object created to be
   used as a hash (`hashes.Hash(hashes.SHA256())`) is a unit at `hashes.Hash`.
   Why: the round-eight annotators split on this (23 of 57 v8 misses on H8 were such objects,
   other annotators excluded them), and the engine reports them as selectors of the call they
   configure. The H8 figures under the round-eight codebook are kept as they were measured.
 - B2g. A standard-library client that is not a cryptographic module (`urllib.request.urlopen`,
   `asyncio.open_connection`, `smtplib`, `imaplib`, `poplib`, `ftplib`, `http.client`) is a unit
   (B, `tls`) under the same rule as B2e: when the call passes a TLS context or turns TLS on,
   including `starttls()` and `start_tls()` on such a client. Classes that always speak TLS
   (`http.client.HTTPSConnection`, `smtplib.SMTP_SSL`, `imaplib.IMAP4_SSL`, `poplib.POP3_SSL`,
   `ftplib.FTP_TLS`) are units whatever their arguments.
 - B2h. A call into a library is a unit wherever it is written, including inside a copy of a
   third-party package bundled in the repository (`vendor/`, a copied `urllib3/`). What is
   excluded is a call to a function the repository's files define, not a call written in them.
 - B2i. An assignment is not a call: `ssl._create_default_https_context =
   ssl._create_unverified_context` is not a unit (the engine reports such references; they
   are scored as false positives, as before).

## R9-C. A new held-out set (H9)

C1. Frame and order as PROTOCOL-R8 C1, continuing at position 376, the first position no earlier
round screened. Exclusions as R8-C2 plus every repository screened in round eight.
C2. Strata, draw and quotas as R8-C3 with seed `"20261019:" + owner/name`: 20 P and 10 G.
C3. Size rule as R8-C4 (at least 120 units and 40 PK+TLS units, else add 5 P up to 35 P).
C4. Labels by separate agents that see only the round-nine codebook and the drawn files; frozen
with a SHA-256 manifest before any engine runs on H9. The v9 source is frozen (SHA-256) before
any H9 label is read, and H9 annotator reports are not used for development.

## R9-D. Measurement

D1. v5, v8 and v9 each run once on H9; matching and metrics as R6-D1 and R6-D2, pooled and per
stratum.
D2. Decision rules, fixed now:
 - Recall: v9's recall on A+B exceeds v8's, and so does its PK+TLS recall on A+B.
 - Precision: v9 has no false positive that v8 lacks, and the Wilson lower bound of v9's
   precision is at least 0.95.
 - Speed (R9-A4): v9 not slower than v8 by more than 5%.
D3. Every miss and false positive of each engine is listed by file and line. Nothing on the
website or README changes in this round.
