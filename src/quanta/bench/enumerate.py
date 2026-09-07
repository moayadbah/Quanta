"""Enumerate every syntactic call, not just scanner positives, for blinded annotation."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from quanta.bench.dataset import check_mutable, read_dataset, write_jsonl
from quanta.config import get_settings
from quanta.core.detect import detect_repository, node_id
from quanta.core.ingest import clone_pinned, scratch_dir, walk_repository
from quanta.core.models import write_canonical_json
from quanta.errors import Reject


def name_of(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{name_of(node.value)}.{node.attr}"
    return "<dynamic>"


def enumerate_tree(root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cfg = get_settings()
    walk = walk_repository(root, cfg)
    detection = detect_repository(walk.files, root, cfg)
    predicted = {(s.file, s.line, s.col): s for s in detection.crypto_calls}
    rows: list[dict[str, Any]] = []
    unparseable = {f.file for f in detection.unparseable}
    for file in walk.files:
        relative = file.relative_to(root).as_posix()
        if relative in unparseable:
            continue
        try:
            source = file.read_text(encoding="utf-8")
            parsed = ast.parse(source)
        except (OSError, UnicodeError, SyntaxError, RecursionError):
            unparseable.add(relative)
            continue
        lines = source.splitlines()
        for node in ast.walk(parsed):
            if not isinstance(node, ast.Call):
                continue
            # AST columns count UTF-8 bytes; LibCST columns count characters.
            col = len(lines[node.lineno - 1].encode()[: node.col_offset].decode())
            site = predicted.get((relative, node.lineno, col))
            rows.append(
                {
                    "site_id": node_id("candidate", relative, node.lineno, col, "call"),
                    "file": relative,
                    "line": node.lineno,
                    "col": col,
                    "qualified_name": name_of(node.func),
                    "detected": site is not None,
                    "detected_site_id": site.site_id if site else None,
                }
            )
    rows.sort(key=lambda r: (r["file"], r["line"], r["col"]))
    return rows, {
        "unparseable": sorted(unparseable),
        "truncations": [t.model_dump() for t in walk.truncations],
        "limitation": "Recall is conditional on syntactic calls in parseable, enumerated files.",
    }


def enumerate_corpus(corpus: Path) -> int:
    root = corpus.parent
    check_mutable(root)
    dataset = read_dataset(corpus)
    if not dataset.repositories:
        raise Reject("BENCHMARK_INVALID", "select the corpus before enumerating candidates")
    count = 0
    for repository in dataset.repositories:
        owner, name = repository.repo.split("/")
        with scratch_dir(parent=get_settings().scratch_root) as scratch:
            source = scratch / "repo"
            clone_pinned(owner, name, repository.commit_sha, source)
            rows, meta = enumerate_tree(source)
        write_jsonl(root / "candidates" / f"{repository.slug}.jsonl", rows)
        write_canonical_json(root / "candidates" / f"{repository.slug}.meta.json", meta)
        count += len(rows)
    return count
