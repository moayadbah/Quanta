# Measurement protocol, round four (written before any result of this round)

Written: 2026-09-24, before any ruleset v3 code and before the new labels. Author: Claude.
Tool under test: `app/` at package 0.4.0, ruleset 2026.10.01 ("v2"), then the round-four ruleset ("v3").
Brief: the owner's round-four direction ("Accuracy is the product. Push it higher.").

## R4-A. A fresh held-out set (S41 to S60)

A1. Same frame, same seeded order (`random.Random(20260923)`), same exclusions, size limit and keep rule as PROTOCOL.md A2 to A4 (the crypto-import list is unchanged, for comparability). Screening resumes at order position 144, where round two stopped, and stops at 20 kept repositories. Output `sample/r4-screening.jsonl`, `sample/r4-kept.json`, clones in `clones/sample-r4/`.
A2. Why: S21 to S40 were labelled blind in round three, but their misses have now been read. They become a development set. Only S41 to S60 are held out in this round.

## R4-B. Labels

B1. Codebook unchanged (PROTOCOL.md B2 to B5): at most 8 files per repository chosen by the seeded rule; units A, B and C; kind recorded for every A and B unit (hash, mac, symmetric, public_key, key_handling, tls, kdf, random, other).
B2. S41 to S60 are labelled before any v3 detection code is written. A manifest with SHA-256 and UTC time is written when labelling ends (`labels/MANIFEST-r4.sha256`).
B3. Single annotator (the model), not blind to the tool's design. Stated as a limit.

## R4-C. Measurement

C1. Sets: D = S01 to S20 (design), H3 = S21 to S40 (development in this round), H4 = S41 to S60 (held out).
C2. Metrics: precision; recall on A; recall on A and B; PK+TLS recall on A; PK+TLS recall on A and B (PK+TLS = public_key, key_handling, tls). Wilson 95% intervals.
C3. During development, every detection change is measured on D and H3 and logged with time in `r4/accuracy-log.jsonl`. H4 is not measured until development ends.
C4. At the end, v2 and v3 are measured once on H4. The website figure is the H4 figure.

## R4-D. Decision rules (fixed now)

D1. v3 improves on public key and TLS if its H4 PK+TLS recall on A and B exceeds v2's, and the Wilson lower bound of v3 is above v2's point estimate.
D2. Precision on H4 must keep a Wilson lower bound of at least 0.85.
D3. If D1 or D2 fails, that is reported as it is, and the website shows the H4 numbers of whichever ruleset ships.

## R4-E. Readiness assessment

E1. Every rule is taken from a published document with URL, date and status (final or draft), stored in `app/config/standards.json`. No rule is invented. Where a primary document could not be read by the annotator, the secondary sources used are named.

## R4-F. Time and cost

F1. No human timing experiment (owner instruction). Published rates are used: code review speed, engineer cost, and published migration effort. The computation and every input are shown behind the number.

## R4-G. Scan robustness

G1. A list of public repositories of varied size, language and shape is run through the product end to end. Every failure is recorded, fixed where possible, and re-run. Results per repository are reported.
