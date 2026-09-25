"""Every ruleset-v2 name resolves against the real library (Master Plan 7.3).

A typo in a qualified name is a silent false negative forever, so each rule's module is
imported and its attribute path walked. Run with ``uv sync --extra dev --extra rulecheck``.
Libraries that are not installed are skipped, not passed.
"""

from __future__ import annotations

import importlib

import pytest

from quanta.core.ruleset_v2 import RULES, SITE_RULES, canonical

#: Real APIs that do not resolve in the check environment, with the reason. Adding a name
#: here needs a reason that is not "the test failed" (evidence/DEVIATIONS.md 16).
UNRESOLVABLE_HERE = {
    "ssl.wrap_socket": "removed in Python 3.12; still present in older code Quanta analyses",
    "oqs.KeyEncapsulation": "liboqs-python needs the native liboqs library",
    "oqs.Signature": "liboqs-python needs the native liboqs library",
    **{
        f"paramiko.DSSKey{suffix}": "DSA keys were removed in paramiko 4.0; old code uses them"
        for suffix in ("", ".generate", ".from_private_key", ".from_private_key_file")
    },
}


def _configure_django() -> None:
    """django.contrib.auth.hashers refuses to import without settings."""
    try:
        from django.conf import settings
    except ImportError:
        return
    if not settings.configured:
        settings.configure()


_configure_django()


def _resolve(name: str) -> bool | None:
    parts = name.split(".")
    for cut in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:cut]))
        except ImportError:
            continue
        for attr in parts[cut:]:
            if not hasattr(obj, attr):
                return False
            obj = getattr(obj, attr)
        return True
    return None  # library not installed


@pytest.mark.parametrize("name", sorted(RULES))
def test_rule_name_resolves(name: str) -> None:
    if name in UNRESOLVABLE_HERE:
        pytest.skip(UNRESOLVABLE_HERE[name])
    resolved = _resolve(name)
    if resolved is None:
        pytest.skip(f"{name.split('.')[0]} is not installed (use --extra rulecheck)")
    assert resolved, f"{name} does not resolve: fix the rule, do not guess"


def test_the_table_covers_public_key_and_tls() -> None:
    categories = {r.category for r in SITE_RULES.values()}
    assert {"tls", "signature", "key_agreement", "key_generation", "key_loading"} <= categories


def test_aliases_match_exactly_never_by_prefix() -> None:
    assert canonical("sha256") == "SHA2-256"
    assert canonical("sha256crypt") is None
    assert canonical("none") is None
    assert canonical("none", token=True) == "JOSE-NONE"
