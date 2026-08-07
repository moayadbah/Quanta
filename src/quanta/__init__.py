"""Quanta — cryptographic agility measurement for Python repositories.

The package splits along the trust boundary described in §4.3:

* ``quanta.core`` — the Analysis Plane. Parses untrusted repository source and **never**
  imports, executes, or installs it.
* ``quanta.engines`` / ``quanta.verify`` — the Research Plane. Executes vetted code only,
  inside hardened containers, and is never reachable from the web tier.
"""

from __future__ import annotations

from quanta.version import CRYPTO_RULESET_VERSION, __version__, analyzer_version

__all__ = ["CRYPTO_RULESET_VERSION", "__version__", "analyzer_version"]
