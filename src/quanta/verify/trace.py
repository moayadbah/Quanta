"""Check the static inventory against what the project's own tests execute (Master Plan 25).

The tests run with :mod:`quanta.verify.trace_plugin`, which records every call from the
project's code into a cryptography library. This module classifies each traced call and
asks: of the algorithm-bearing lines the tests executed, how many did static analysis
find? The answer is a per-repository recall, measured on the repository itself, with the
missed lines listed. It covers only code the tests run, and says so.

Classification (fixed in round two, before results; X.509 value objects moved to IGNORE
in round three as Master Plan 25.3 specifies):

* IGNORE: output and bookkeeping (``update``, ``hexdigest``, ``public_bytes``, ...), and
  X.509 name, attribute and extension objects, which configure no algorithm.
* B: operations on crypto objects (``sign``, ``verify``, ``encrypt``, ``wrap_socket``...).
* C: randomness and constant-time comparison.
* A: every other traced crypto callee. These are the algorithm-bearing lines.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from quanta.core.roles import classify_role

IGNORE = frozenset(
    {
        "update",
        "finalize",
        "digest",
        "hexdigest",
        "copy",
        "public_bytes",
        "private_bytes",
        "public_key",
        "private_bytes_raw",
        "public_bytes_raw",
        "key_size",
        "curve",
        "name",
        "digest_size",
        "block_size",
        "__init__",
        "__call__",
        "__enter__",
        "__exit__",
        "private_numbers",
        "public_numbers",
        "authenticate_additional_data",
        "finalize_with_tag",
        "tag",
    }
)
B_OPS = frozenset(
    {
        "sign",
        "verify",
        "encrypt",
        "decrypt",
        "exchange",
        "derive",
        "encryptor",
        "decryptor",
        "wrap_socket",
        "wrap_bio",
        "load_cert_chain",
        "load_verify_locations",
        "set_ciphers",
    }
)
C_OPS = frozenset({"compare_digest", "token_bytes", "token_hex", "token_urlsafe"})

#: X.509: only loading a certificate or building one chooses anything. Name, attribute and
#: extension objects and their accessors are values (round two, 22.6b).
X509_A = frozenset(
    {
        "load_pem_x509_certificate",
        "load_der_x509_certificate",
        "load_pem_x509_csr",
        "load_der_x509_csr",
        "CertificateBuilder",
        "CertificateSigningRequestBuilder",
    }
)

#: Algorithm objects passed as arguments on their own line (``hashes.SHA256()`` inside
#: ``PBKDF2HMAC(...)``) are part of the enclosing call. A line whose only A callees come
#: from these modules is not counted as a separate algorithm-bearing line (round two, D2).
SELECTOR_MODULES = (
    "cryptography.hazmat.primitives.hashes.",
    "cryptography.hazmat.primitives.ciphers.algorithms.",
    "cryptography.hazmat.primitives.ciphers.modes.",
    "cryptography.hazmat.primitives.asymmetric.padding.",
    "cryptography.hazmat.primitives.asymmetric.ec.SECP",
    "cryptography.hazmat.primitives.asymmetric.ec.ECDSA",
)

#: Below this, a percentage would describe too little to mean anything.
MIN_EXECUTED_LINES = 3


def classify(callee: str) -> str | None:
    """``"A"``, ``"B"``, ``"C"`` or ``None`` (ignored) for a traced callee name."""
    last = callee.rsplit(".", 1)[-1]
    if callee.startswith("cryptography.x509."):
        if last in X509_A:
            return "A"
        return "B" if last == "sign" else None
    if last in IGNORE:
        return None
    if last in B_OPS:
        return "B"
    if last in C_OPS:
        return "C"
    return "A"


@dataclass
class TraceCheck:
    """How much of the executed cryptography the static inventory found."""

    executed_a_lines: int = 0
    found_by_static: int = 0
    recall: float | None = None
    missed: list[dict[str, Any]] = field(default_factory=list)
    static_not_executed: int = 0
    too_few: bool = True
    note: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "executed_a_lines": self.executed_a_lines,
            "found_by_static": self.found_by_static,
            "recall_on_executed": None if self.recall is None else round(self.recall, 4),
            "missed": self.missed,
            "static_sites_not_executed": self.static_not_executed,
            "too_few_to_judge": self.too_few,
            "note": self.note,
        }


def read_trace(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def static_lines(cdg: dict[str, Any]) -> set[tuple[str, int]]:
    """Lines where static analysis placed a crypto site (a call or a reference)."""
    return {
        (str(n["file"]).replace("\\", "/"), int(n["line"]))
        for n in cdg.get("nodes", [])
        if n.get("kind") == "crypto_call"
    }


def check(trace: list[dict[str, Any]], cdg: dict[str, Any]) -> TraceCheck:
    """Compare traced algorithm-bearing lines in shipped code with the static inventory."""
    classes: dict[tuple[str, int], set[str]] = {}
    callees: dict[tuple[str, int], list[str]] = {}
    selector_only: dict[tuple[str, int], bool] = {}
    for record in trace:
        file = str(record["file"])
        if classify_role(file) != "source":
            continue
        kind = classify(str(record["callee"]))
        if kind is None:
            continue
        key = (file, int(record["line"]))
        classes.setdefault(key, set()).add(kind)
        callees.setdefault(key, []).append(str(record["callee"]))
        is_selector = str(record["callee"]).startswith(SELECTOR_MODULES)
        selector_only[key] = selector_only.get(key, True) and (is_selector or kind != "A")
    executed = {k for k, v in classes.items() if "A" in v and not selector_only.get(k, False)}
    found = static_lines(cdg)
    hit = executed & found
    shipped_static = {k for k in found if classify_role(k[0]) == "source"}
    result = TraceCheck(
        executed_a_lines=len(executed),
        found_by_static=len(hit),
        recall=(len(hit) / len(executed)) if executed else None,
        missed=[
            {"file": f, "line": ln, "callees": sorted(set(callees[(f, ln)]))[:4]}
            for f, ln in sorted(executed - found)
        ],
        static_not_executed=len(shipped_static - set(classes)),
        too_few=len(executed) < MIN_EXECUTED_LINES,
    )
    if not executed:
        result.note = "The tests executed no algorithm-bearing crypto lines in shipped code."
    elif result.too_few:
        result.note = "Too few executed crypto lines to judge recall."
    return result
