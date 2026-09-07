"""Blinded CSV worksheets and validated annotation import."""

from __future__ import annotations

import csv
from pathlib import Path

from quanta.bench.dataset import check_mutable, read_dataset, read_jsonl, write_jsonl
from quanta.errors import Reject

FIELDS = ("site_id", "file", "line", "col", "qualified_name", "label", "notes")
LABELS = frozenset({"crypto", "non_crypto"})


def worksheet(root: Path, annotator: str) -> list[Path]:
    check_mutable(root)
    if annotator not in {"a1", "a2", "a3"}:
        raise Reject("BENCHMARK_INVALID", "annotator must be a1, a2 or a3")
    outputs: list[Path] = []
    for repository in read_dataset(root / "dataset.lock.json").repositories:
        rows = read_jsonl(root / "candidates" / f"{repository.slug}.jsonl")
        if annotator == "a3":
            a1 = {
                r["site_id"]: r["label"]
                for r in read_jsonl(root / "labels" / f"{repository.slug}.a1.jsonl")
            }
            a2 = {
                r["site_id"]: r["label"]
                for r in read_jsonl(root / "labels" / f"{repository.slug}.a2.jsonl")
            }
            rows = [r for r in rows if a1.get(r["site_id"]) != a2.get(r["site_id"])]
        path = root / "worksheets" / f"{repository.slug}.{annotator}.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise Reject("BENCHMARK_INVALID", f"worksheet already exists: {path.name}")
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            for row in rows:
                # Scanner predictions are deliberately absent from the worksheet.
                blinded = {k: row.get(k, "") for k in FIELDS}
                for key, value in blinded.items():
                    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
                        blinded[key] = "'" + value
                writer.writerow(blinded)
        outputs.append(path)
    return outputs


def import_worksheet(root: Path, path: Path, annotator: str) -> Path:
    check_mutable(root)
    if annotator not in {"a1", "a2", "a3"}:
        raise Reject("BENCHMARK_INVALID", "annotator must be a1, a2 or a3")
    dataset = read_dataset(root / "dataset.lock.json")
    repo = next((r for r in dataset.repositories if path.name == f"{r.slug}.{annotator}.csv"), None)
    if repo is None:
        raise Reject(
            "BENCHMARK_INVALID", "worksheet filename does not identify a corpus repository"
        )
    candidates = read_jsonl(root / "candidates" / f"{repo.slug}.jsonl")
    expected = {row["site_id"] for row in candidates}
    if annotator == "a3":
        a1 = {
            r["site_id"]: r["label"] for r in read_jsonl(root / "labels" / f"{repo.slug}.a1.jsonl")
        }
        a2 = {
            r["site_id"]: r["label"] for r in read_jsonl(root / "labels" / f"{repo.slug}.a2.jsonl")
        }
        expected = {sid for sid in expected if a1.get(sid) != a2.get(sid)}
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    ids = [r.get("site_id") for r in rows]
    if set(ids) != expected or len(ids) != len(set(ids)):
        raise Reject("BENCHMARK_INVALID", "worksheet has missing, extra or duplicate candidate ids")
    if any(row.get("label") not in LABELS for row in rows):
        raise Reject("BENCHMARK_INVALID", "every candidate needs a crypto or non_crypto label")
    records = [
        {
            "site_id": r["site_id"],
            "label": r["label"],
            "notes": r.get("notes", ""),
            "annotator": annotator,
        }
        for r in rows
    ]
    destination = (
        root / "adjudication" / f"{repo.slug}.jsonl"
        if annotator == "a3"
        else root / "labels" / f"{repo.slug}.{annotator}.jsonl"
    )
    write_jsonl(destination, sorted(records, key=lambda r: r["site_id"]))
    return destination
