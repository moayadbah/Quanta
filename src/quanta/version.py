"""Version identifiers that participate in the provenance triple.

Every artifact records ``{repo, commit_sha, analyzer_version}`` (INGEST-04). Detection
results are only reproducible relative to the crypto ruleset, so the ruleset version is
folded into ``analyzer_version`` rather than tracked separately.
"""

from __future__ import annotations

__version__ = "0.2.0"

#: Crypto ruleset version (§9.5). Bump whenever ``core.rules`` changes in a way that
#: could alter detection output — it invalidates the analysis cache by design.
CRYPTO_RULESET_VERSION = "2026.08.01"


def analyzer_version() -> str:
    """Return the composite analyzer version used in the provenance triple."""
    return f"{__version__}+rules.{CRYPTO_RULESET_VERSION}"
