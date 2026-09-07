"""Bounded CycloneDX 1.6 imports. Only located assets enter the source graph.

Occurrence coordinates follow the official 1.6 JSON schema. Unlocated assets are counted
explicitly; they are not invented source locations. Embedded snippets are never retained.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from quanta.core.detect import DetectionResult, module_name, node_id
from quanta.core.models import CryptoSite
from quanta.core.rules import classify_algorithm
from quanta.errors import Reject

MAX_CBOM_BYTES = 2_000_000
MAX_COMPONENTS = 20_000


@dataclass
class CbomImport:
    sha256: str
    sites: list[CryptoSite] = field(default_factory=list)
    unlocated: int = 0


def _location(value: Any) -> tuple[str, int, int] | None:
    if not isinstance(value, dict):
        raise Reject("CBOM_INVALID", "occurrence must be an object")
    raw = value.get("location")
    line = value.get("line")
    if not isinstance(raw, str) or not isinstance(line, int) or isinstance(line, bool):
        return None
    path = PurePosixPath(raw)
    if (
        not raw
        or len(raw) > 500
        or "\\" in raw
        or ":" in raw
        or any(ord(c) < 32 or ord(c) == 127 for c in raw)
        or path.is_absolute()
        or ".." in path.parts
        or path.suffix not in {".py", ".pyi"}
        or not 1 <= line <= 999_999_999
    ):
        return None
    # CycloneDX 'offset' is a byte offset, not a source column; do not equate them.
    return path.as_posix(), line, 0


def read_cbom(path: Path) -> CbomImport:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CBOM_BYTES + 1)
        if len(raw) > MAX_CBOM_BYTES:
            raise Reject("CBOM_INVALID", "CBOM exceeds the 2 MB limit")
        payload = json.loads(raw)
    except (OSError, ValueError, RecursionError) as exc:
        raise Reject("CBOM_INVALID", "CBOM must be readable JSON") from exc
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        raise Reject("CBOM_INVALID", "expected a CycloneDX object")
    if payload.get("specVersion") != "1.6":
        raise Reject("CBOM_INVALID", "only CycloneDX 1.6 is supported")
    result = CbomImport(sha256=hashlib.sha256(raw).hexdigest())
    pending = payload.get("components", [])
    if not isinstance(pending, list):
        raise Reject("CBOM_INVALID", "components must be an array")
    pending = list(pending)
    count = 0
    while pending:
        component = pending.pop()
        count += 1
        if count > MAX_COMPONENTS or not isinstance(component, dict):
            raise Reject("CBOM_INVALID", "invalid or excessive components")
        children = component.get("components", [])
        if not isinstance(children, list):
            raise Reject("CBOM_INVALID", "nested components must be an array")
        pending.extend(children)
        if component.get("type") != "cryptographic-asset":
            continue
        name = component.get("name")
        if not isinstance(name, str) or not name or len(name) > 200:
            raise Reject("CBOM_INVALID", "cryptographic assets need a bounded name")
        evidence = component.get("evidence", {})
        if not isinstance(evidence, dict):
            raise Reject("CBOM_INVALID", "evidence must be an object")
        occurrences = evidence.get("occurrences", [])
        if not isinstance(occurrences, list):
            raise Reject("CBOM_INVALID", "occurrences must be an array")
        if not occurrences:
            result.unlocated += 1
        for occurrence in occurrences:
            location = _location(occurrence)
            if location is None:
                result.unlocated += 1
                continue
            file, line, col = location
            symbol = occurrence.get("symbol", f"cbom.{name}")
            if not isinstance(symbol, str) or len(symbol) > 500:
                raise Reject("CBOM_INVALID", "invalid occurrence symbol")
            weak, quantum = classify_algorithm(name)
            result.sites.append(
                CryptoSite(
                    site_id=node_id("crypto_call", file, line, col, symbol),
                    file=file,
                    line=line,
                    col=col,
                    qualified_name=symbol,
                    algorithm=name,
                    module=module_name(Path(file), Path()),
                    source="cbom",
                    weak=weak,
                    quantum_vulnerable=quantum,
                )
            )
    result.sites.sort(key=lambda site: (site.file, site.line, site.qualified_name))
    return result


def merge_cbom(detection: DetectionResult, cbom: CbomImport) -> None:
    def key(algorithm: str | None) -> str:
        return (algorithm or "").upper().replace("-", "").replace("_", "")

    existing = list(detection.crypto_calls)
    for site in cbom.sites:
        if any(
            s.file == site.file
            and s.line == site.line
            and (s.qualified_name == site.qualified_name or key(s.algorithm) == key(site.algorithm))
            for s in existing
        ):
            continue
        detection.sites.append(site)
        existing.append(site)
        detection.modules.add(site.module)
        literal = site.model_copy(
            update={
                "site_id": node_id(
                    "algo_literal", site.file, site.line, site.col, site.algorithm or ""
                ),
                "kind": "algo_literal",
                "parent_site_id": site.site_id,
            }
        )
        detection.sites.append(literal)
    detection.sites.sort(key=lambda s: (s.file, s.line, s.col, s.site_id))
