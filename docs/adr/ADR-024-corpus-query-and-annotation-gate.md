# ADR-024: Executable corpus query and independent annotation gate

Status: Accepted. Clarifies the implementation of ADR-012; does not waive the gate.

## Verified query correction

On 2026-09-07, GitHub rejected the document's query
`language:python stars:>500 pushed:>2025-08-01 NOT is:archived` with HTTP 422, explaining
that logical operators do not apply to qualifiers. The equivalent query with
`archived:false` succeeded. Use:

```text
language:python stars:>500 pushed:>2025-08-01 archived:false
```

The selector snapshots up to GitHub's first 1,000 search results, then orders by decreasing
stars and increasing full repository name. This sampling-frame limit is recorded, not
claimed to represent every matching repository. Accepted candidates still require the
specified Python LOC range, tests, an accepted OSI license, and detected cryptographic
calls; four are taken in each size band. A conservative SPDX allowlist may exclude other
OSI licenses and that reason is logged. No target dependencies are installed or executed.
Selection resumes from its saved catalog and audit after transient API failures. A moved
head is recorded as a rejection, never silently substituted for the pinned SHA.

## Annotation and freeze

A list made only of detector positives cannot expose false negatives. Enumerate all
syntactic calls in parseable, budgeted files, then omit predictions from the CSV worksheets.
This can create substantially more annotation work than the document's anticipated few
hundred crypto sites. Report precision and recall as conditional on that candidate
universe; neither metric measures non-call assets or files that could not be parsed.

The researcher supplies the real identities of two independent annotators and a third
adjudicator. Every candidate must be labelled by both; disagreements need adjudication.
The freeze checks all 12 repositories, size strata, accepted selection records, labels and
supported Python versions, fingerprints the research inputs, and creates a local commit
and `dataset-v1` tag after a clean-worktree check. It never pushes automatically.

**There is no completed benchmark in this revision.** The empty draft manifest is an
honest initial state. No labels, agreement figures, engine outcomes or independent reviews
are invented. E0/E1/E2, P0/P1 rewriting, target-code verification and fork PR automation
remain behind the document's explicit freeze-before-engine requirement.

Statistical functions can be tested independently using synthetic unit-test data. The
committed sensitivity and collinearity examples use the three existing demo reports;
they are demonstration outputs, not twelve-repository research results. Unverified and
refused outcomes are counted separately from the binary McNemar denominator. Bootstrap
resampling uses entire repositories, with its percentile method and random seed recorded.
