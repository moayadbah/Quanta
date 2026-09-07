"""Versioned research data and explicit freeze validation. No manufactured labels."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from quanta.core.ingest import parse_repo_url
from quanta.core.models import write_canonical_json
from quanta.errors import Reject

QUERY = "language:python stars:>500 pushed:>2025-08-01 archived:false"


class Repository(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repo: str
    commit_sha: str = Field(pattern=r"^[a-f0-9]{40}$")
    license: str = Field(min_length=1)
    python_version: str | None = Field(default=None, pattern=r"^3\.\d{1,2}$")
    python_loc: int = Field(ge=1000, le=100000)
    stars: int = Field(gt=500)
    band: Literal["small", "medium", "large"]
    exclusion: str | None = None

    @field_validator("repo")
    @classmethod
    def valid_repo(cls, value: str) -> str:
        owner, name = parse_repo_url(f"https://github.com/{value}")
        return f"{owner}/{name}"

    @model_validator(mode="after")
    def size_band_matches(self) -> Repository:
        expected = (
            "small" if self.python_loc < 5000 else "medium" if self.python_loc <= 30000 else "large"
        )
        if self.band != expected:
            raise ValueError("size band does not match Python LOC")
        return self

    @property
    def slug(self) -> str:
        return self.repo.replace("/", "--")


class Dataset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"
    status: Literal["draft", "frozen"] = "draft"
    selection_query: str = QUERY
    repositories: list[Repository] = Field(default_factory=list)
    # Filled by the real annotators, not by a scanner or generated defaults.
    annotators: dict[str, str] = Field(default_factory=dict)
    sha256: dict[str, str] = Field(default_factory=dict)


def read_dataset(path: Path) -> Dataset:
    try:
        data = Dataset.model_validate_json(path.read_text())
    except (OSError, ValueError) as exc:
        raise Reject("BENCHMARK_INVALID", "invalid or missing dataset.lock.json") from exc
    names = [r.repo.lower() for r in data.repositories]
    if len(names) != len(set(names)):
        raise Reject("BENCHMARK_INVALID", "dataset contains duplicate repositories")
    return data


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    except (OSError, ValueError) as exc:
        raise Reject("BENCHMARK_INVALID", f"invalid or missing {path.name}") from exc
    if any(not isinstance(record, dict) for record in records):
        raise Reject("BENCHMARK_INVALID", "JSONL records must be objects")
    return records


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows))


def check_mutable(root: Path) -> None:
    if read_dataset(root / "dataset.lock.json").status == "frozen":
        raise Reject(
            "BENCHMARK_NOT_FROZEN", "frozen data cannot be modified; create a new dataset version"
        )


def fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_freeze(root: Path) -> Dataset:
    dataset = read_dataset(root / "dataset.lock.json")
    if dataset.status != "frozen" or not dataset.sha256:
        raise Reject("BENCHMARK_NOT_FROZEN", "independent labels and a dataset freeze are required")
    for relative, digest in dataset.sha256.items():
        path = root / relative
        if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
            raise Reject("BENCHMARK_INVALID", "unsafe manifest path")
        if not path.is_file() or fingerprint(path) != digest:
            raise Reject("BENCHMARK_INVALID", f"frozen data changed: {relative}")
    return dataset


def freeze(root: Path) -> Dataset:
    from quanta.bench.agreement import agreement

    check_mutable(root)
    dataset = read_dataset(root / "dataset.lock.json")
    if len(dataset.repositories) != 12:
        raise Reject("BENCHMARK_INVALID", "freeze requires exactly 12 pinned repositories")
    if any(
        sum(r.band == band for r in dataset.repositories) != 4
        for band in ("small", "medium", "large")
    ):
        raise Reject("BENCHMARK_INVALID", "freeze requires four repositories in each size band")
    names = [dataset.annotators.get(k, "").strip() for k in ("a1", "a2", "a3")]
    if not all(names) or len({n.casefold() for n in names}) != 3:
        raise Reject(
            "BENCHMARK_INVALID", "record three distinct annotator identities before freezing"
        )
    selection = root / "selection_log.jsonl"
    audit = read_jsonl(selection)
    for repo in dataset.repositories:
        if not any(
            row.get("decision") == "accept"
            and row.get("repo") == repo.repo
            and row.get("commit_sha") == repo.commit_sha
            for row in audit
        ):
            raise Reject("BENCHMARK_INVALID", f"missing accepted selection record for {repo.repo}")
    if any(repo.python_version is None for repo in dataset.repositories):
        raise Reject("BENCHMARK_INVALID", "record a supported Python version for every repository")
    report = agreement(root, require_adjudication=True)
    write_canonical_json(root / "agreement.json", report)
    paths = [selection, root / "agreement.json"]
    catalog = root / "selection_catalog.json"
    if catalog.exists():
        paths.append(catalog)
    for repo in dataset.repositories:
        paths.append(root / "candidates" / f"{repo.slug}.jsonl")
        metadata = root / "candidates" / f"{repo.slug}.meta.json"
        if metadata.exists():
            paths.append(metadata)
        paths.extend(root / "labels" / f"{repo.slug}.{a}.jsonl" for a in ("a1", "a2"))
        adjudication = root / "adjudication" / f"{repo.slug}.jsonl"
        if adjudication.exists():
            paths.append(adjudication)
    dataset.sha256 = {p.relative_to(root).as_posix(): fingerprint(p) for p in sorted(paths)}
    dataset.status = "frozen"
    write_canonical_json(root / "dataset.lock.json", dataset)
    return dataset
