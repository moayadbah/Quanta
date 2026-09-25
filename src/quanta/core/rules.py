"""Public ruleset names, derived from ruleset v2 (Master Plan 7.3).

Older modules and tests import these names. They are now computed from
:mod:`quanta.core.ruleset_v2` so there is exactly one table to keep correct.

Editing the table is a ruleset change. Bump ``CRYPTO_RULESET_VERSION`` when you do;
the analysis cache keys on it, so a stale version silently serves stale findings.
"""

from __future__ import annotations

from typing import Final

from quanta.core.ruleset_v2 import (
    ALGORITHMS,
    CRYPTO_MODULE_PREFIXES,
    SITE_RULES,
    canonical,
)
from quanta.version import CRYPTO_RULESET_VERSION

__all__ = [
    "CRYPTO_MODULE_PREFIXES",
    "CRYPTO_QUALIFIED_NAMES",
    "CRYPTO_RULESET_VERSION",
    "QUANTUM_VULNERABLE",
    "WEAK_ALGORITHMS",
    "classify_algorithm",
    "is_crypto_name",
    "patch_contains_forbidden_import",
]

#: Every qualified name that is a crypto call site.
CRYPTO_QUALIFIED_NAMES: Final[frozenset[str]] = frozenset(SITE_RULES)

#: Broken or deprecated today, independently of quantum adversaries.
WEAK_ALGORITHMS: Final[frozenset[str]] = frozenset(a for a, i in ALGORITHMS.items() if i.weak)

#: Broken by a cryptographically relevant quantum computer: the migration target set.
QUANTUM_VULNERABLE: Final[frozenset[str]] = frozenset(
    a for a, i in ALGORITHMS.items() if i.quantum_vulnerable
)

_FORBIDDEN_EMIT_PREFIXES: Final[tuple[str, ...]] = ("import oqs", "from oqs")


def is_crypto_name(qualified_name: str) -> bool:
    """True when a resolved qualified name is a crypto call site."""
    return qualified_name in SITE_RULES


def classify_algorithm(name: str) -> tuple[bool, bool]:
    """Return ``(weak, quantum_vulnerable)`` for an algorithm name or canonical id."""
    algorithm = name if name in ALGORITHMS else canonical(name)
    info = ALGORITHMS.get(algorithm) if algorithm else None
    if info is None:
        return (False, False)
    return (info.weak, info.quantum_vulnerable)


def patch_contains_forbidden_import(diff: str) -> bool:
    """DoD-E4: does a unified diff **add** an ``oqs`` import?

    Only added lines count. A migration that *removes* an existing ``oqs`` import is
    precisely the improvement Quanta wants to make, so flagging removals would refuse the
    good outcome along with the bad one.
    """
    for line in diff.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        stripped = line[1:].strip()
        if any(stripped.startswith(prefix) for prefix in _FORBIDDEN_EMIT_PREFIXES):
            return True
    return False
