# ADR-018 — Deterministic built-in SVG renderer; Graphviz optional

**Status:** Accepted
**Date:** 2026-08-08
**Amends §3.11 (Reporting: "Jinja2 + Graphviz/pydot") of the Technical Documentation.**

## Context

The report must embed the CDG as **inline SVG** in a self-contained `report.html` that opens
from `file://` with no network and no server (PROC-07, NFR-07, DoD-C5). §3.11 nominates
Graphviz via pydot.

Three facts pull against that as the *default* path:

1. **Graphviz is a system binary, not a Python dependency.** `pip install pydot` does not
   install `dot`. It was absent on the development host. Every developer machine, CI runner
   and container image would need it provisioned separately — a moving part in a project
   whose stated design rule is "prefer fewer moving parts" (§11.3 rule 2).
2. **NFR-03 requires byte-identical output** for the same provenance triple. Graphviz layout
   is a heuristic that has changed between releases; identical input can lay out differently
   under a different `dot` version. That converts a system-package upgrade into a
   determinism failure, which DoD-C3 checks for.
3. **The graph being drawn is small and already structured.** Nodes are crypto sites,
   literals, config reads, functions and modules — a layered, mostly-DAG shape that a
   deterministic layered layout renders adequately without a general-purpose engine.

## Decision

`core/report.py` uses a **built-in pure-Python layered SVG emitter** by default. Layout is a
deterministic function of the sorted node and edge lists, so identical CDG input yields
byte-identical SVG.

Graphviz is **retained as an optional renderer**, selected by `[report].renderer = "graphviz"`
in `config/default.toml`. `pydot` stays in `[project.dependencies]` per §9.2, so this is a
default change, not a dependency removal.

## Consequences

- No system dependency for the default path; `report.html` remains self-contained.
- Determinism is a property of our own code and is unit-testable.
- The built-in layout is visually plainer than Graphviz's, and will degrade on very dense
  graphs. Accepted: the report's load-bearing content is the cited deduction list and the
  factor table, not the picture. Users wanting publication-quality figures set
  `renderer = "graphviz"`.
- Two renderers must be kept in agreement on the SVG contract (inline, no external refs, no
  script). Both are covered by `tests/security/test_report_escaping.py`.

## Revisit trigger

The built-in layout becomes unreadable on real corpus repositories, **and** the determinism
requirement is relaxed or Graphviz is pinned by version in the container image.
