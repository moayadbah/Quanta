# From the first milestone to today

The Numbers section compares the original working implementation at
`a0cdc2f95a4ba6093b7bd8aa8ae5366d536cc3c9` with the current shipped code. That
commit records the first milestone, before the first web demonstration. It is not
the later engine previously used as the website's comparison baseline.

| Source inventory | When we started | Today |
| --- | ---: | ---: |
| Explicit named call rules | 28 | 457 |
| Distinct top-level library/module namespaces in those rules | 9 | 51 |
| Guided migration recipes in the catalog | 0 | 8 |

These are implementation inventory counts. A rule is one named API entry, not an
algorithm, a detected occurrence or an independent measure of accuracy. Module
namespaces include standard-library modules and are not a count of third-party
packages. The catalog count does not mean every guide applies to every scan.

`project-progress.json` records the original call names, the source commit and
source hashes. `project_progress.py` regenerates that file and the `progress`
block in the public `src/quanta/web/static/evidence.json`:

```bash
uv run python evidence/project_progress.py
```

A full checkout with the baseline commit is required. The current code's named
rules come from `SITE_RULES`; the current guide count comes from
`config/migrations.json`. No guide/proposal catalog exists at the original
milestone, whose documented output is the dependency graph, agility score and
report.

## Techniques

The original implementation uses syntax-tree parsing, exact qualified-name
matching, nearby algorithm literals, configuration-read heuristics, dependency
graphs and a weighted agility score. See the baseline's `core/detect.py`,
`core/rules.py`, `core/graph.py` and `core/score.py`.

The current implementation adds wider API rules, algorithm selectors and
defaults, local alias/object tracking, separate shipped/test/example roles,
standards-based readiness and reviewed proposals with guided migration recipes.
See `core/detect.py`, `core/operations.py`, `core/ruleset_v2.py`, `core/roles.py`,
`core/readiness.py`, `core/fixes.py` and the guide catalog. The website does
not present experimental work or a future AI verification layer as shipped.

## Current measurements

The current accuracy figures remain 95.0% recall for other crypto calls, 79.3%
for public key/TLS, and 96.3% precision, from `figures-v9.json`. The broader-scope
recall is 82.1%. These numbers, their samples and their limitations are unchanged.
The initial milestone documented synthetic-fixture tests and explicitly deferred
real-world accuracy measurement. No equivalent early accuracy rate is invented,
and the later engine's result is not relabelled as the initial result.
