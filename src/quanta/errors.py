"""Error taxonomy.

Two rules hold everywhere in Quanta:

* Clients receive a **stable machine-readable** ``error_code``, never a raw traceback
  (§5.2.4). Internal detail is logged against a correlation id instead.
* A budget overrun is a *declared truncation*, never a silent partial result (INGEST-08).
"""

from __future__ import annotations

from typing import Final

#: Stable machine-readable codes. The value is the code; the mapping documents the
#: HTTP status the web tier will attach to it, so the taxonomy lives in one place.
ERROR_CODES: Final[dict[str, int]] = {
    "URL_MALFORMED": 400,
    "HOST_NOT_ALLOWED": 400,
    "REPO_NOT_FOUND": 404,
    "REPO_PRIVATE": 404,
    "REPO_TOO_LARGE": 413,
    "SHA_MISMATCH": 409,
    "CLONE_FAILED": 502,
    "CLONE_TIMEOUT": 504,
    "GITHUB_UNAVAILABLE": 502,
    "RATE_LIMITED": 429,
    "NOT_FINISHED": 409,
    "ANALYSIS_TIMEOUT": 504,
    "INTERNAL": 500,
}


class QuantaError(Exception):
    """Base class for every error Quanta raises deliberately."""


class Reject(QuantaError):
    """Input refused at a trust boundary.

    ``code`` must be a key of :data:`ERROR_CODES` so the web tier can map it to a status
    without a second lookup table.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"unknown error code: {code!r}")
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)

    @property
    def http_status(self) -> int:
        return ERROR_CODES[self.code]


class Truncated(QuantaError):
    """A corpus budget was exhausted during traversal (INGEST-08).

    Carries the reason and the limit so the analysis can record a *declared truncation*
    in ``meta.json`` and the report, instead of dropping files silently.
    """

    def __init__(self, reason: str, limit: int, observed: int) -> None:
        self.reason = reason
        self.limit = limit
        self.observed = observed
        super().__init__(f"corpus budget exhausted: {reason} (limit={limit}, observed={observed})")
