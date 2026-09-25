"""pytest plugin: record calls into cryptography libraries made from project code.

Copied into the sandbox and loaded with ``-p quanta_trace``. Standard library only, and
no ``quanta`` imports, because it runs inside the project's own environment.

Uses ``sys.monitoring`` (PEP 669, Python 3.12). For every call whose callee belongs to a
crypto module and whose caller file is inside the working tree, it records (caller file,
caller line, callee name). Calls made from outside the tree are switched off per location
after their first event (``DISABLE``), which keeps the overhead small: round two measured
0.2 s on a 9 s suite and under 1 s on a 75 s suite.

Output: JSON lines at ``$QUANTA_TRACE_OUT``.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PREFIXES = (
    "hashlib",
    "_hashlib",
    "hmac",
    "_hmac",
    "ssl",
    "_ssl",
    "cryptography",
    "Crypto",
    "Cryptodome",
    "nacl",
    "jwt",
    "jose",
    "oqs",
    "truststore",
    "_blake2",
    "_sha",
    "_md5",
)
ROOT = os.environ.get("QUANTA_TRACE_ROOT", "/work")
TOOL = 4
_seen: Counter[tuple[str, int, str]] = Counter()
_monitoring: Any = getattr(sys, "monitoring", None)


def _callee_name(obj: Any) -> str | None:
    owner = getattr(obj, "__objclass__", None)  # method descriptor, e.g. a Rust-backed key
    if owner is not None:
        module = getattr(owner, "__module__", "") or ""
        if module.startswith(PREFIXES):
            return f"{module}.{owner.__qualname__}.{getattr(obj, '__name__', '?')}"
        return None
    module = getattr(obj, "__module__", None)
    name = getattr(obj, "__qualname__", None) or getattr(obj, "__name__", None)
    bound = getattr(obj, "__self__", None)
    if bound is not None and not isinstance(bound, type(sys)):
        bound_module = type(bound).__module__
        if bound_module and bound_module.startswith(PREFIXES):
            return f"{bound_module}.{type(bound).__qualname__}.{getattr(obj, '__name__', '?')}"
    if isinstance(bound, type(sys)):  # builtin function of a module, e.g. _hashlib.openssl_sha256
        module = bound.__name__
    if module and module.startswith(PREFIXES):
        return f"{module}.{name}"
    return None


def _on_call(code: Any, offset: int, callable_: Any, arg0: Any) -> Any:
    filename = code.co_filename
    if not filename.startswith(ROOT):
        return _monitoring.DISABLE
    callee_code = getattr(callable_, "__code__", None) or getattr(
        getattr(callable_, "__func__", None), "__code__", None
    )
    if callee_code is not None and callee_code.co_filename.startswith(ROOT):
        return None  # defined inside the analysed repository (for example pyjwt's own `jwt`)
    name = _callee_name(callable_)
    if name is None:
        return None
    module = sys.modules.get(getattr(callable_, "__module__", "") or "")
    if module is not None and (getattr(module, "__file__", "") or "").startswith(ROOT):
        return None  # a class or function defined in the analysed tree
    frame = sys._getframe(1)
    rel = os.path.relpath(filename, ROOT).replace(os.sep, "/")
    _seen[(rel, frame.f_lineno, name)] += 1
    return None


def pytest_configure(config: Any) -> None:
    if _monitoring is None:
        return
    _monitoring.use_tool_id(TOOL, "quanta-trace")
    _monitoring.register_callback(TOOL, _monitoring.events.CALL, _on_call)
    _monitoring.set_events(TOOL, _monitoring.events.CALL)


def pytest_unconfigure(config: Any) -> None:
    if _monitoring is None:
        return
    _monitoring.set_events(TOOL, 0)
    out = os.environ.get("QUANTA_TRACE_OUT")
    if out:
        with Path(out).open("w", encoding="utf-8") as handle:
            for (file, line, name), count in sorted(_seen.items()):
                handle.write(
                    json.dumps({"file": file, "line": line, "callee": name, "count": count}) + "\n"
                )
