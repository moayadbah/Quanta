"""File roles (Master Plan 7.2, fixes D4).

Only ``source`` files describe the architecture of the shipped product, so only they
count toward the score. Every other role still appears in the inventory and the CBOM:
a migration must change test vectors too, it just should not be scored on them.
"""

from __future__ import annotations

from typing import Literal

Role = Literal["source", "test", "docs", "example", "vendored", "tooling"]

ROLES: tuple[Role, ...] = ("source", "test", "docs", "example", "vendored", "tooling")

_TEST_DIRS = frozenset({"tests", "test", "testing"})
_DOCS_DIRS = frozenset({"docs", "doc"})
_EXAMPLE_DIRS = frozenset({"examples", "example", "samples", "sample", "demo", "demos"})
_VENDORED_DIRS = frozenset({"vendor", "vendored", "_vendor", "third_party", "extern"})
_TOOLING_DIRS = frozenset({"scripts", "tools", "benchmarks", "benchmark", "bench", "ci"})


def classify_role(rel_posix_path: str) -> Role:
    """Role of a repository file, from its POSIX path relative to the repository root.

    First matching rule wins. Matching is case-insensitive on whole path segments.
    """
    parts = rel_posix_path.lower().split("/")
    name, dirs = parts[-1], set(parts[:-1])
    if (
        dirs & _TEST_DIRS
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    ):
        return "test"
    if dirs & _DOCS_DIRS:
        return "docs"
    if dirs & _EXAMPLE_DIRS:
        return "example"
    if dirs & _VENDORED_DIRS:
        return "vendored"
    if dirs & _TOOLING_DIRS:
        return "tooling"
    return "source"
