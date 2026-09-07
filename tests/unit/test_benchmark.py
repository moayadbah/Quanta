from __future__ import annotations

import csv
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

import pytest

from quanta.bench import selection
from quanta.bench.agreement import agreement
from quanta.bench.dataset import (
    QUERY,
    Dataset,
    Repository,
    freeze,
    read_jsonl,
    verify_freeze,
    write_jsonl,
)
from quanta.bench.enumerate import enumerate_tree
from quanta.bench.worksheet import import_worksheet, worksheet
from quanta.core.models import write_canonical_json
from quanta.errors import Reject


def make_dataset(root: Path, *, size: int = 1) -> Dataset:
    repositories = [
        Repository(
            repo=f"o/r{i}",
            commit_sha="a" * 40,
            license="MIT",
            python_loc=(1001, 10001, 40001)[i // 4] if size == 12 else 1001,
            python_version="3.12",
            stars=501,
            band=("small", "medium", "large")[i // 4] if size == 12 else "small",
        )
        for i in range(size)
    ]
    data = Dataset(repositories=repositories)
    write_canonical_json(root / "dataset.lock.json", data)
    for repo in repositories:
        rows = [
            {
                "site_id": "c1",
                "file": "app.py",
                "line": 1,
                "col": 0,
                "qualified_name": "hashlib.sha1",
                "detected": True,
            },
            {
                "site_id": "c2",
                "file": "app.py",
                "line": 2,
                "col": 0,
                "qualified_name": "print",
                "detected": False,
            },
        ]
        write_jsonl(root / "candidates" / f"{repo.slug}.jsonl", rows)
    return data


def test_candidate_list_contains_scanner_negatives_and_never_runs_source(tmp_path: Path) -> None:
    (tmp_path / "input.py").write_text(
        "import hashlib\nhashlib.sha1(b'x')\nunknown_crypto()\nraise RuntimeError('do not run')\n"
    )
    candidates, meta = enumerate_tree(tmp_path)
    assert len(candidates) == 3
    assert sum(c["detected"] for c in candidates) == 1
    assert meta["unparseable"] == []


def test_blinded_worksheets_reject_incomplete_labels(tmp_path: Path) -> None:
    make_dataset(tmp_path)
    file = worksheet(tmp_path, "a1")[0]
    text = file.read_text(encoding="utf-8-sig")
    assert "detected" not in text
    with pytest.raises(Reject, match="every candidate"):
        import_worksheet(tmp_path, file, "a1")
    with file.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    rows[0]["label"] = "crypto"
    rows[1]["label"] = "non_crypto"
    with file.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    assert import_worksheet(tmp_path, file, "a1").is_file()


def test_freeze_requires_independent_labels_and_detects_later_tampering(tmp_path: Path) -> None:
    data = make_dataset(tmp_path, size=12)
    with pytest.raises(Reject, match="three distinct"):
        freeze(tmp_path)
    data.annotators = {"a1": "Annotator One", "a2": "Annotator Two", "a3": "Adjudicator"}
    write_canonical_json(tmp_path / "dataset.lock.json", data)
    write_jsonl(
        tmp_path / "selection_log.jsonl",
        [
            {"decision": "accept", "repo": repo.repo, "commit_sha": repo.commit_sha}
            for repo in data.repositories
        ],
    )
    with pytest.raises(Reject):
        freeze(tmp_path)
    for repo in data.repositories:
        for annotator in ("a1", "a2"):
            write_jsonl(
                tmp_path / "labels" / f"{repo.slug}.{annotator}.jsonl",
                [{"site_id": "c1", "label": "crypto"}, {"site_id": "c2", "label": "non_crypto"}],
            )
    report = agreement(tmp_path)
    assert report["overall"]["krippendorff_alpha"] == 1
    assert report["overall"]["exact_agreement_pct"] == 100
    assert report["detection"]["precision"] == report["detection"]["recall"] == 1
    freeze(tmp_path)
    assert verify_freeze(tmp_path).status == "frozen"
    file = tmp_path / "labels" / f"{data.repositories[0].slug}.a1.jsonl"
    file.write_text(file.read_text() + "\n")
    with pytest.raises(Reject, match="frozen data changed"):
        verify_freeze(tmp_path)


def test_missing_disagreement_resolution_cannot_be_frozen(tmp_path: Path) -> None:
    data = make_dataset(tmp_path)
    repo = data.repositories[0]
    write_jsonl(
        tmp_path / "labels" / f"{repo.slug}.a1.jsonl",
        [{"site_id": "c1", "label": "crypto"}, {"site_id": "c2", "label": "non_crypto"}],
    )
    write_jsonl(
        tmp_path / "labels" / f"{repo.slug}.a2.jsonl",
        [{"site_id": "c1", "label": "non_crypto"}, {"site_id": "c2", "label": "non_crypto"}],
    )
    assert agreement(tmp_path)["detection"]["unresolved"] == 1
    with pytest.raises(Reject, match="unresolved disagreements"):
        agreement(tmp_path, require_adjudication=True)


@pytest.mark.parametrize("code", sorted(selection.TRANSIENT_FAILURES))
def test_acquisition_failure_cannot_exclude_a_repository_or_change_sampling_order(
    tmp_path: Path, code: str
) -> None:
    write_canonical_json(tmp_path / "dataset.lock.json", Dataset())
    write_canonical_json(
        tmp_path / "selection_catalog.json",
        {
            "query": QUERY,
            "items": [
                {
                    "full_name": f"{owner}/repo",
                    "stargazers_count": stars,
                    "license": {"spdx_id": "MIT"},
                    "size": 1,
                    "archived": False,
                    "language": "Python",
                }
                for owner, stars in (("first", 2000), ("second", 1000))
            ],
        },
    )
    # Older audit entries used 'reject' for transport failures; they must be retried too.
    write_jsonl(
        tmp_path / "selection_log.jsonl",
        [{"repo": "first/repo", "decision": "reject", "code": code}],
    )
    with (
        patch.object(selection.httpx, "Client", return_value=nullcontext(object())),
        patch.object(
            selection, "resolve_metadata", side_effect=Reject(code, "temporary")
        ) as resolve,
        pytest.raises(Reject, match="temporary"),
    ):
        selection.select(tmp_path)
    assert resolve.call_count == 1
    assert resolve.call_args.args[:2] == ("first", "repo")
    assert read_jsonl(tmp_path / "selection_log.jsonl")[-1]["decision"] == "defer"
