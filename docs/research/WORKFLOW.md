# Complete the Quanta benchmark

The software prepares and validates the work; real independent annotations are required
before migration engines may be written. This is the gate in sections 2.4, 6 and 11 of the
technical document. The committed corpus is a draft with no selected repositories.

## 1. Prepare candidates

Install the locked research environment:

```bash
uv sync --locked --extra research --extra dev
uv run quanta bench select
uv run quanta bench enumerate --corpus benchmark/dataset.lock.json
uv run quanta bench worksheet --annotator a1
uv run quanta bench worksheet --annotator a2
```

Selection may need more than the anonymous GitHub API quota. On a transient API failure,
wait for the quota to recover and rerun `bench select`; the saved catalog preserves the
ordering and accepted pins. The selector never asks for a token in the analysis service.
A corpus that does not fill all size bands stays a partial draft with explicit rejections.
Candidate enumeration rejects a moved repository head rather than changing its pin.

The JSONL candidate files retain detector predictions for evaluation. Give each annotator
only their corresponding CSV worksheets and access to the pinned source. Do not give one
annotator the other's decisions. Inspect candidate metadata for omitted or unparseable
files; the reported recall is limited to the enumerated candidate universe.

## 2. Independently classify and adjudicate

Fill every `label` cell with `crypto` or `non_crypto`; `notes` is optional. Keep the
`site_id` and worksheet filename unchanged. Import each completed file:

```bash
uv run quanta bench import --annotator a1 --worksheet benchmark/worksheets/OWNER--REPO.a1.csv
uv run quanta bench import --annotator a2 --worksheet benchmark/worksheets/OWNER--REPO.a2.csv
uv run quanta bench agree
uv run quanta bench worksheet --annotator a3
```

Replace `OWNER--REPO` with an actual generated filename. The a3 worksheets contain only
disagreements. Import each completed a3 worksheet using the same `bench import` command
with `--annotator a3`. Agreement is published both as nominal Krippendorff alpha and exact
agreement percentage. Alpha is `null`, with a reason, when the label distribution is
constant. Detector precision and recall have separate denominators and unresolved counts.

Record the three real identities under `annotators` in `dataset.lock.json` using keys
`a1`, `a2`, `a3`. Set each repository's `python_version` to a version compatible with its
pinned project metadata. The selector leaves it unspecified instead of inventing support.

## 3. Freeze before implementing engines

```bash
uv run quanta bench agree
git add benchmark
git commit -m "Complete independent corpus annotations"
uv run quanta bench freeze
```

Freeze refuses incomplete or inconsistent data and requires a clean working tree. It
fingerprints candidates, labels, adjudication, the selection audit and agreement, then
commits the manifest and creates `dataset-v1`. Publication of the tag is a separate action.
The pre-registered `weights-v1` tag identifies the original, unchanged 0.30/0.30/0.20/0.20
weights. No engine outcomes have been collected or used to tune them.

After this gate, implement E0, E1, E2 for P0, then the offline verification harness, then P1,
in the document's order. Verification of target code belongs on a disposable, credential-free
VM in hardened containers. The existing X-Wing shim and its 1,000-example property tests
are available; rewriting and target-test execution are not available in this revision.

## 4. Reproduce statistics

These runnable examples use the three committed demo analyses:

```bash
uv run quanta stats sensitivity --scores demo/corpus --out docs/research/demo-statistics
uv run quanta stats collinearity --scores demo/corpus --out docs/research/demo-statistics
```

They demonstrate the analysis code, not the benchmark's final results. Three observations
are too few for a research conclusion. Correlated factors are reported and never silently
removed or reweighted after outcomes.

The future engine-result JSONL contract is one record per `(repo, site_id, pattern, engine)`:

```json
{"repo":"owner/name","site_id":"candidate-id","pattern":"p0","engine":"e2","status":"unverified"}
```

Statuses are `passed`, `failed`, `unverified`, or `refused`. Keep missing coverage and
refusals explicit. With real results and one score per repository available:

```bash
uv run quanta stats all --data benchmark/results.jsonl --scores benchmark/scores --out benchmark/statistics
```

McNemar comparisons are paired by repository, site and pattern. Bootstrap confidence
intervals resample entire repositories. The output records the seed, resampling method,
excluded observations and undefined values rather than replacing missing results with zero.
