from __future__ import annotations

import multiprocessing as mp
import os
import socket
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from quanta.core.ingest import parse_repo_url, remove_tree, walk_repository
from quanta.errors import Reject
from quanta.web.app import create_app
from quanta.web.sandbox import block_network
from quanta.web.store import ArtifactStore


@pytest.mark.parametrize(
    "raw",
    [
        " https://github.com/o/r",
        "https://@github.com/o/r",
        "https://github.com:/o/r",
        "https://github.com//o/r",
        "https://github.com/o/r//",
    ],
)
def test_url_normalization_cannot_hide_empty_components(raw: str) -> None:
    with pytest.raises(Reject):
        parse_repo_url(raw)


def test_artifact_store_rejects_traversal_and_symlinks(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    with pytest.raises(Reject):
        store.put("../escape", "report.html", b"bad")
    job = "33333333-3333-4333-8333-333333333333"
    outside = tmp_path / "outside"
    outside.mkdir()
    (store.root / job).symlink_to(outside, target_is_directory=True)
    with pytest.raises(Reject):
        store.put(job, "report.html", b"bad")
    assert not (outside / "report.html").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX special file fixture")
def test_special_files_are_not_parsed(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe.py")
    assert walk_repository(tmp_path).files == []


def test_cleanup_of_a_symlink_never_changes_the_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o755)
    (outside / "keep.txt").write_text("keep")
    link = tmp_path / "link"
    link.symlink_to(outside, target_is_directory=True)
    permissions = outside.stat().st_mode
    remove_tree(link)
    assert not link.is_symlink()
    assert outside.stat().st_mode == permissions
    assert (outside / "keep.txt").read_text() == "keep"


def _network_cutoff(pipe: object) -> None:
    # Created before cutoff so a 'socket' rule alone is insufficient to pass.
    existing = socket.socket()
    try:
        block_network(required=True)
        try:
            socket.socket()
            pipe.send("new socket was permitted")
            return
        except PermissionError:
            pass
        try:
            existing.connect(("127.0.0.1", 9))
            pipe.send("existing socket connect was permitted")
        except PermissionError:
            pipe.send("blocked")
    except Reject:
        pipe.send("unavailable")
    finally:
        existing.close()
        pipe.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux kernel control")
def test_kernel_filter_blocks_new_and_existing_sockets() -> None:
    context = mp.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(target=_network_cutoff, args=(child,))
    process.start()
    try:
        assert parent.poll(10)
        result = parent.recv()
        assert result == "blocked", result
    finally:
        process.join(2)
        if process.is_alive():
            process.kill()
            process.join()
        parent.close()
        child.close()


def test_schema_errors_are_problem_json_without_reflecting_input(tmp_path: Path) -> None:
    with TestClient(create_app(tmp_path / "artifacts")) as client:
        response = client.post("/api/v1/analyses", json={"repo_url": ["sensitive-sample"]})
        assert response.status_code == 422
        assert response.headers["content-type"].startswith("application/problem+json")
        assert response.json()["error_code"] == "SCHEMA_INVALID"
        assert "sensitive-sample" not in response.text
        assert (
            client.get("/api/v1/does-not-exist")
            .headers["content-type"]
            .startswith("application/problem+json")
        )
