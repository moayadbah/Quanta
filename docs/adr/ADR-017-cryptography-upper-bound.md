# ADR-017 — Bound `cryptography` to `>=48.0.0,<49`

**Status:** Accepted
**Date:** 2026-08-08
**Supersedes nothing. Amends §9.2 of the Technical Documentation.**

## Context

§9.2 specifies `cryptography>=48.0.0` with no upper bound, and §3.11 states the lockfile is
the source of truth for exact versions. That is right in principle, but an unbounded floor
resolves to the newest release, and the newest releases cannot be installed on the
development hardware.

Measured facts:

| Version | macOS wheels published |
|---|---|
| 48.0.0, 48.0.1 | `macosx_10_9_universal2` (x86_64 **and** arm64) |
| 49.0.0, 50.0.0 | `macosx_11_0_arm64` **only** |

`cryptography` 47.0.0 deprecated x86_64 macOS wheels and removed them in 49.0.0. The
development host is an **x86_64** Mac. Resolving to ≥49 therefore triggers a source build
requiring Rust ≥1.83 and OpenSSL ≥3.5 — slow, fragile, and a barrier for a three-person
undergraduate team that gains nothing.

The requirement §9.2 actually encodes is *"a build in which ML-KEM is available"*. That is
satisfied from 48.0.0 onward, verified on this host:

```
cryptography 48.0.1, OpenSSL 4.0.1
ML-KEM-768 available; ct=1088, ss=32, pk=1184, seed=64; round-trip ok
```

## Decision

Pin `cryptography>=48.0.0,<49` in `pyproject.toml`.

## Consequences

- ML-KEM-768 and ML-DSA remain available — 48.0.0 is precisely the release that made
  post-quantum algorithms reachable from the project's OpenSSL wheels.
- The environment installs from wheels on both x86_64 and arm64 macOS, and on Linux.
- Security patches published only in the ≥49 line would not be picked up automatically.
  Mitigated by Dependabot/Renovate on the pinned range (A06) and by the fact that the
  Analysis Plane holds no credentials and executes no target code.
- FFDH deprecation landed in 50.0.0; irrelevant here, since `dh.generate_parameters` is a
  *detection rule* in §9.5, not a Quanta call site.

## Revisit trigger

Development moves to Apple Silicon, or the workflow becomes Docker-only (where
`manylinux_2_34_x86_64` wheels exist for every version). Either removes the constraint, and
the bound should be dropped back to `>=48.0.0`.
