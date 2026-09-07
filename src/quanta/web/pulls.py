"""Publish exactly the reviewed diff on a dedicated branch; retry without duplicate PRs."""

from __future__ import annotations

import base64
import hashlib
import re
import time
from typing import Any, cast
from urllib.parse import quote

import httpx

from quanta.core.fixes import FixPlan, review, safe_path
from quanta.errors import Reject
from quanta.web.auth import Identity, github_client
from quanta.web.db import timestamp
from quanta.web.jobs import JobRegistry


def api(client: httpx.Client, method: str, path: str, **kwargs: Any) -> Any:
    try:
        response = client.request(method, path, **kwargs)
        if response.status_code == 401:
            raise Reject("AUTH_REQUIRED", "GitHub authorization expired. Sign in again.")
        if response.status_code in {403, 429}:
            raise Reject(
                "GITHUB_UNAVAILABLE",
                "GitHub refused this request. Check your access "
                "or try again after its rate limit resets.",
            )
        if response.status_code >= 300:
            raise Reject(
                "PR_CONFLICT",
                "GitHub could not complete this operation. "
                "Check repository access, then retry or scan again.",
            )
        return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise Reject(
            "GITHUB_UNAVAILABLE", "GitHub is unavailable. Your review is saved; retry shortly."
        ) from exc


def _github_url(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[1-9][0-9]*", value
    ):
        raise Reject("GITHUB_UNAVAILABLE", "GitHub returned an invalid pull request URL.")
    return value


def _publish(
    client: httpx.Client,
    row: dict[str, Any],
    identity: Identity,
    result: dict[str, Any],
    branch: str,
) -> str:
    slug = f"{row['repo_owner']}/{row['repo_name']}"
    base = f"/repos/{slug}"
    repository = api(client, "GET", base)
    if repository.get("private") or repository.get("archived") or repository.get("disabled"):
        raise Reject("PR_CONFLICT", "Pull requests require an active public repository.")
    if repository["default_branch"] != row["default_branch"]:
        raise Reject("REVIEW_STALE", "The default branch changed. Run a new scan.")
    direct = bool(repository.get("permissions", {}).get("push"))
    owner = row["repo_owner"] if direct else identity.login
    destination = slug if direct else f"{identity.login}/{row['repo_name']}"
    target = f"/repos/{destination}"
    head = f"{owner}:{branch}"
    existing = api(
        client,
        "GET",
        base + "/pulls",
        params={"head": head, "base": row["default_branch"], "state": "all"},
    )
    if existing:
        return _github_url(existing[0]["html_url"])
    current = api(client, "GET", base + "/commits/" + quote(row["default_branch"], safe=""))
    if current["sha"] != row["commit_sha"]:
        raise Reject(
            "REVIEW_STALE",
            "The repository changed since this scan. Scan again before opening a PR.",
        )
    if not direct:
        response = client.get(target)
        if response.status_code == 404:
            api(client, "POST", base + "/forks", json={"default_branch_only": True})
            raise Reject("PR_PENDING", "GitHub is preparing your fork. Retry in a few seconds.")
        fork = api(client, "GET", target)
        origin = repository.get("source", repository)["full_name"].lower()
        if (
            not fork.get("fork")
            or fork.get("source", {}).get("full_name", "").lower() != origin
            or fork.get("owner", {}).get("id") != int(identity.user_id)
        ):
            raise Reject(
                "PR_CONFLICT",
                "A repository with that name exists in your account "
                "and is not a fork of this project.",
            )

    commit = api(client, "GET", base + "/git/commits/" + row["commit_sha"])
    tree_sha = commit["tree"]["sha"]
    trees: dict[str, list[dict[str, Any]]] = {}
    entries = []
    for file in result["files"]:
        if not safe_path(file["path"]):
            raise Reject("FIX_UNAVAILABLE")
        parent = tree_sha
        entry: dict[str, Any] = {}
        parts = file["path"].split("/")
        for index, part in enumerate(parts):
            if parent not in trees:
                trees[parent] = api(client, "GET", base + "/git/trees/" + parent)["tree"]
            entry = next((e for e in trees[parent] if e["path"] == part), {})
            if not entry or (index < len(parts) - 1 and entry.get("type") != "tree"):
                raise Reject("REVIEW_STALE", "A reviewed file no longer matches the scan.")
            parent = entry["sha"]
        if entry.get("mode") not in {"100644", "100755"} or entry.get("type") != "blob":
            raise Reject("FIX_UNAVAILABLE", "Only regular Python files can be changed.")
        original = api(client, "GET", base + "/git/blobs/" + entry["sha"])
        if original.get("encoding") != "base64" or original.get("size", 0) > 100_000:
            raise Reject("REVIEW_STALE", "The original source could not be verified.")
        raw = base64.b64decode(original["content"])
        if hashlib.sha256(raw).hexdigest() != file["before_sha256"]:
            raise Reject("REVIEW_STALE", "The original source changed. Scan again.")
        entries.append(
            {
                "path": file["path"],
                "mode": entry["mode"],
                "type": "blob",
                "content": file["content"],
            }
        )
    tree = api(client, "POST", target + "/git/trees", json={"base_tree": tree_sha, "tree": entries})
    reference = client.get(target + "/git/ref/heads/" + branch)
    if reference.status_code == 200:
        branch_commit = api(
            client, "GET", target + "/git/commits/" + reference.json()["object"]["sha"]
        )
        if branch_commit["tree"]["sha"] != tree["sha"] or [
            p["sha"] for p in branch_commit["parents"]
        ] != [row["commit_sha"]]:
            raise Reject(
                "PR_CONFLICT",
                "The Quanta branch was changed on GitHub. It will not be overwritten.",
            )
    elif reference.status_code == 404:
        created = api(
            client,
            "POST",
            target + "/git/commits",
            json={
                "message": "Replace selected weak hashes with SHA-256",
                "tree": tree["sha"],
                "parents": [row["commit_sha"]],
            },
        )
        api(
            client,
            "POST",
            target + "/git/refs",
            json={"ref": "refs/heads/" + branch, "sha": created["sha"]},
        )
    else:
        raise Reject("GITHUB_UNAVAILABLE", "Could not check the Quanta branch. Retry shortly.")
    body = (
        "Replaces the hash calls explicitly selected and reviewed in Quanta.\n\n"
        f"Scanned commit: `{row['commit_sha']}`\n\n"
        "Validation: Python syntax checked. Repository tests were not run.\n\n"
        + result["compatibility"]
        + "\n\n"
        "Please run your repository's tests and review compatibility before merging.\n\n"
        f"Review digest: `{result['digest']}`"
    )
    pull = api(
        client,
        "POST",
        base + "/pulls",
        json={
            "title": "Replace selected weak hashes with SHA-256",
            "head": head,
            "base": row["default_branch"],
            "body": body,
            "draft": True,
            "maintainer_can_modify": False,
        },
    )
    return _github_url(pull["html_url"])


def open_pull(
    registry: JobRegistry,
    job_id: str,
    identity: Identity,
    plan: FixPlan,
    selected: list[str],
    digest: str,
) -> str:
    result = review(plan, selected)
    if result["digest"] != digest:
        raise Reject("REVIEW_STALE", "Review the current diff before opening a pull request.")
    key = hashlib.sha256(f"{identity.user_id}:{job_id}:{digest}".encode()).hexdigest()
    with registry.db.connect(write=True) as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row or row["status"] != "succeeded" or row["cached"]:
            raise Reject("FIX_UNAVAILABLE", "Pull requests require a completed live scan.")
        previous = conn.execute("SELECT * FROM pull_requests WHERE id=?", (key,)).fetchone()
        if previous and previous["url"]:
            return cast(str, previous["url"])
        if (
            previous
            and previous["status"] == "creating"
            and previous["updated_at"] > timestamp(time.time() - 240)
        ):
            raise Reject("PR_PENDING", "Your pull request is being prepared. Retry shortly.")
        conn.execute(
            "INSERT INTO pull_requests(id,job_id,user_id,digest,status,updated_at) "
            "VALUES(?,?,?,?,'creating',?) ON CONFLICT(id) DO UPDATE "
            "SET status='creating',updated_at=excluded.updated_at",
            (key, job_id, identity.user_id, digest, timestamp()),
        )
        metadata = dict(row)
    try:
        with github_client(identity.token) as client:
            url = _publish(client, metadata, identity, result, "quanta/hash-upgrade-" + key[:16])
    except Exception:
        with registry.db.connect(write=True) as conn:
            conn.execute(
                "UPDATE pull_requests SET status='retry',updated_at=? WHERE id=?",
                (timestamp(), key),
            )
        raise
    with registry.db.connect(write=True) as conn:
        conn.execute(
            "UPDATE pull_requests SET status='created',url=?,updated_at=? WHERE id=?",
            (url, timestamp(), key),
        )
    return url
