"""Deterministic corpus selection with an append-only candidate audit trail."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from quanta.bench.dataset import QUERY, Dataset, Repository, check_mutable, read_dataset, read_jsonl
from quanta.config import get_settings
from quanta.core.detect import detect_repository
from quanta.core.ingest import (
    _get_json,
    clone_pinned,
    resolve_metadata,
    scratch_dir,
    walk_repository,
)
from quanta.core.models import write_canonical_json
from quanta.errors import Reject

# OSI-approved SPDX identifiers accepted automatically. Unknown/custom licenses require
# review rather than an optimistic acceptance. Source: https://opensource.org/licenses
OSI_LICENSES = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "MPL-2.0",
        "Zlib",
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "Unlicense",
        "Python-2.0",
        "BSL-1.0",
        "EPL-2.0",
    }
)


def select(root: Path, *, pages: int = 10) -> Dataset:
    cfg = get_settings()
    path = root / "dataset.lock.json"
    root.mkdir(parents=True, exist_ok=True)
    if path.exists():
        check_mutable(root)
        dataset = read_dataset(path)
    else:
        dataset = Dataset()
    if len(dataset.repositories) == 12:
        return dataset
    log = root / "selection_log.jsonl"

    def record(payload: dict[str, Any]) -> None:
        with log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")

    candidates: dict[str, dict[str, Any]] = {}
    with httpx.Client(
        timeout=30,
        follow_redirects=False,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "quanta"},
    ) as http:
        catalog_path = root / "selection_catalog.json"
        if catalog_path.exists():
            payload = json.loads(catalog_path.read_text())
            if payload.get("query") != QUERY:
                raise Reject("BENCHMARK_INVALID", "saved selection query does not match")
            candidates = {item["full_name"]: item for item in payload["items"]}
        else:
            for page in range(1, min(10, pages) + 1):
                request = http.build_request(
                    "GET",
                    "https://api.github.com/search/repositories",
                    params={
                        "q": QUERY,
                        "sort": "stars",
                        "order": "desc",
                        "per_page": 100,
                        "page": page,
                    },
                )
                payload = _get_json(http, str(request.url))
                if payload.get("incomplete_results"):
                    raise Reject(
                        "BENCHMARK_INVALID",
                        "GitHub returned incomplete search results; retry selection",
                    )
                items = payload.get("items", [])
                if not isinstance(items, list):
                    raise Reject("GITHUB_UNAVAILABLE", "invalid search response")
                for item in items:
                    candidates[item["full_name"]] = {
                        key: item.get(key)
                        for key in (
                            "full_name",
                            "stargazers_count",
                            "license",
                            "size",
                            "archived",
                            "language",
                        )
                    }
                if len(items) < 100:
                    break
            record(
                {
                    "event": "sampling_frame",
                    "query": QUERY,
                    "candidate_count": len(candidates),
                    "search_result_cap": min(10, pages) * 100,
                    "ordering": "descending stars, ascending repository name",
                }
            )
            write_canonical_json(catalog_path, {"query": QUERY, "items": list(candidates.values())})
        processed = {
            row.get("repo")
            for row in read_jsonl(log)
            if row.get("decision") in {"accept", "reject"}
            and row.get("code") not in {"RATE_LIMITED", "GITHUB_UNAVAILABLE"}
        }
        ordered = sorted(
            candidates.values(), key=lambda r: (-r["stargazers_count"], r["full_name"])
        )
        for item in ordered:
            slug = item["full_name"]
            if slug in processed:
                continue
            reason = None
            license_id = (item.get("license") or {}).get("spdx_id", "NOASSERTION")
            if license_id not in OSI_LICENSES:
                reason = "license requires manual OSI verification"
            elif item.get("size", 0) > cfg.ingest.max_repo_kb:
                reason = "repository exceeds ingestion size cap"
            elif item.get("archived") or item.get("language") != "Python":
                reason = "repository no longer matches selection query"
            if reason:
                record({"repo": slug, "decision": "reject", "reason": reason})
                continue
            try:
                owner, name = slug.split("/")
                metadata = resolve_metadata(owner, name, cfg, http)
                with scratch_dir(parent=cfg.scratch_root) as scratch:
                    source = scratch / "repo"
                    clone_pinned(owner, name, metadata.commit_sha, source, cfg)
                    walk = walk_repository(source, cfg)
                    if walk.truncated:
                        raise Reject(
                            "BENCHMARK_INVALID", "truncated source cannot enter the corpus"
                        )
                    loc = sum(len(p.read_bytes().splitlines()) for p in walk.files)
                    if not 1000 <= loc <= 100000:
                        raise Reject("BENCHMARK_INVALID", "Python LOC outside 1000..100000")
                    band = "small" if loc < 5000 else "medium" if loc <= 30000 else "large"
                    if sum(r.band == band for r in dataset.repositories) == 4:
                        raise Reject(
                            "BENCHMARK_INVALID", f"{band} band already has four repositories"
                        )
                    has_tests = any("tests" in p.relative_to(source).parts for p in walk.files)
                    test_config = False
                    for filename in ("pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini"):
                        candidate = source / filename
                        if (
                            candidate.is_file()
                            and not candidate.is_symlink()
                            and candidate.stat().st_size < 2_000_000
                        ):
                            test_config |= b"pytest" in candidate.read_bytes()
                    if not (has_tests or test_config):
                        raise Reject(
                            "BENCHMARK_INVALID", "no tests directory or pytest configuration"
                        )
                    detection = detect_repository(walk.files, source, cfg)
                    if not detection.crypto_calls:
                        raise Reject(
                            "BENCHMARK_INVALID", "no rule-matched cryptographic call sites"
                        )
                repository = Repository(
                    repo=slug,
                    commit_sha=metadata.commit_sha,
                    license=license_id,
                    python_loc=loc,
                    stars=item["stargazers_count"],
                    band=band,
                )
                dataset.repositories.append(repository)
                record(
                    {
                        "repo": slug,
                        "decision": "accept",
                        "reason": "all selection criteria met",
                        "commit_sha": metadata.commit_sha,
                        "python_loc": loc,
                        "band": band,
                        "stars": item["stargazers_count"],
                        "license": license_id,
                    }
                )
                write_canonical_json(path, dataset)
            except Reject as exc:
                record({"repo": slug, "decision": "reject", "reason": exc.detail, "code": exc.code})
                if exc.code in {"RATE_LIMITED", "GITHUB_UNAVAILABLE"}:
                    raise
            if len(dataset.repositories) == 12:
                break
    write_canonical_json(path, dataset)
    if len(dataset.repositories) != 12:
        raise Reject(
            "BENCHMARK_INVALID",
            "sampling frame did not fill all bands; partial draft and audit saved",
        )
    return dataset
