"""The environment handed to git, on both platforms.

Every clone on Windows failed with an empty ``CLONE_FAILED``, because the environment was
POSIX-only in four places at once: a ``PATH`` of ``/usr/bin:/bin`` that cannot reach
``git-remote-https.exe``, ``GIT_CONFIG_GLOBAL=/dev/null`` and ``GIT_ASKPASS=/bin/true``
naming files that do not exist there, and no ``SystemRoot``, without which the child cannot
initialise WinSock.

CI runs on Linux, so the Windows branch is exercised here through the ``_is_windows``
indirection. A test that only ever sees the platform it runs on would have passed
throughout the outage.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from quanta.config import IngestSettings, Settings
from quanta.core import ingest
from quanta.core.ingest import _git_env, _git_search_path, hooks_path

# ---------------------------------------------------------------------------------------
# Properties that must hold everywhere
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("platform", ["posix", "nt"])
def test_user_configuration_is_excluded_on_both_platforms(
    platform: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole point of the minimal environment, and it must survive the Windows fix."""
    monkeypatch.setattr(ingest, "_is_windows", lambda: platform == "nt")
    env = _git_env(tmp_path / "clone")

    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert not Path(env["GIT_CONFIG_GLOBAL"]).exists()
    assert "APPDATA" not in env, "the user's gitconfig lives there"
    assert not any(k.lower().endswith("proxy") for k in env), "egress must stay explicit"


@pytest.mark.parametrize("platform", ["posix", "nt"])
def test_hooks_path_never_exists(
    platform: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hook would be attacker-supplied code running during checkout."""
    monkeypatch.setattr(ingest, "_is_windows", lambda: platform == "nt")
    assert not Path(hooks_path(tmp_path / "clone")).exists()


# ---------------------------------------------------------------------------------------
# The Windows branch, exercised from any host
# ---------------------------------------------------------------------------------------


def test_windows_gets_the_variables_without_which_git_cannot_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ingest, "_is_windows", lambda: True)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setenv("COMSPEC", r"C:\Windows\system32\cmd.exe")

    env = _git_env(tmp_path / "clone")

    assert env["SystemRoot"] == r"C:\Windows"
    assert env["COMSPEC"] == r"C:\Windows\system32\cmd.exe"
    assert "GIT_ASKPASS" not in env, "/bin/true does not exist on Windows"


def test_windows_path_carries_gits_own_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Git finds git-remote-https and its TLS DLLs through PATH, nowhere else."""
    monkeypatch.setattr(ingest, "_is_windows", lambda: True)
    install = tmp_path / "Git"
    for part in ("cmd", "mingw64/bin", "usr/bin"):
        (install / part).mkdir(parents=True)

    search = _git_search_path(str(install / "cmd" / "git.exe"))
    entries = search.split(os.pathsep)

    assert str(install / "mingw64" / "bin") in entries
    assert str(install / "usr" / "bin") in entries
    assert str(install / "cmd") in entries
    assert "/usr/bin" not in entries, "the POSIX path is meaningless on Windows"


def test_unrecognised_windows_layout_falls_back_rather_than_breaking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A portable or scoop install should degrade to working, not to a blank PATH."""
    monkeypatch.setattr(ingest, "_is_windows", lambda: True)
    monkeypatch.setenv("PATH", r"C:\some\where")

    # A git.exe sitting alone, with none of the usual sibling directories.
    lonely = tmp_path / "nested" / "git.exe"
    lonely.parent.mkdir(parents=True)

    assert _git_search_path(str(lonely)) != ""


def test_posix_keeps_its_pinned_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ingest, "_is_windows", lambda: False)
    env = _git_env(tmp_path / "clone")

    assert env["PATH"] == "/usr/bin:/bin"
    assert env["GIT_ASKPASS"] == "/bin/true"


@pytest.mark.parametrize("proxy", [None, "http://github-egress:8080"])
def test_acquisition_proxy_is_explicit_and_cannot_inherit_user_credentials(
    proxy: str | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://user:secret@untrusted.test:8080")
    monkeypatch.setenv("NO_PROXY", "*")
    sha = "a" * 40
    cfg = Settings(ingest=IngestSettings(proxy_url=proxy))
    with patch.object(ingest.subprocess, "run") as run:
        run.side_effect = [
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0, stdout=sha + "\n"),
        ]
        ingest.clone_pinned("owner", "repo", sha, tmp_path / "repo", cfg)
    # Clone, sparse-checkout and checkout (which fetches the Python blobs) all go through
    # the explicit proxy and never inherit the user's environment.
    for call in run.call_args_list[:3]:
        assert f"http.proxy={proxy or ''}" in call.args[0]
        assert all("proxy" not in name.lower() for name in call.kwargs["env"])
        assert "secret" not in str(call)
    clone = run.call_args_list[0].args[0]
    assert "--filter=blob:none" in clone
    assert "--no-recurse-submodules" in clone


def test_renamed_repository_follows_only_same_host_api_redirects() -> None:
    """GitHub answers a renamed repository with 301 to /repositories/{id}. Quanta follows
    that one hop only when it stays on https://api.github.com, then re-validates the name."""
    import httpx

    repo = {"full_name": "newowner/newname", "default_branch": "main", "size": 10, "private": False}
    commit = {"sha": "b" * 40}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/old/name":
            return httpx.Response(
                301, headers={"location": "https://api.github.com/repositories/42"}
            )
        if path == "/repos/evil/name":
            return httpx.Response(
                301, headers={"location": "https://attacker.test/repositories/42"}
            )
        if path == "/repositories/42":
            return httpx.Response(200, json=repo)
        if path == "/repos/newowner/newname/commits/main":
            return httpx.Response(200, json=commit)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    meta = ingest.resolve_metadata("old", "name", Settings(), client)
    assert (meta.owner, meta.name, meta.commit_sha) == ("newowner", "newname", "b" * 40)
    with pytest.raises(ingest.Reject) as refused:
        ingest.resolve_metadata("evil", "name", Settings(), client)
    assert refused.value.code == "GITHUB_UNAVAILABLE"


def test_rate_limited_api_falls_back_to_the_git_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    """60 anonymous API requests an hour would stop a public deployment within minutes.
    When the API says so, the head commit and default branch come from git ls-remote."""
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "API rate limit exceeded"})

    listing = "ref: refs/heads/main\tHEAD\n" + "c" * 40 + "\tHEAD\n"
    seen: list[list[str]] = []

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=listing)

    monkeypatch.setattr(ingest.subprocess, "run", fake_run)
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    meta = ingest.resolve_metadata("owner", "repo", Settings(), client)
    assert (meta.default_branch, meta.commit_sha, meta.size_kb) == ("main", "c" * 40, 0)
    assert "ls-remote" in seen[0] and "http.followRedirects=false" in seen[0]


def test_listing_without_a_default_branch_is_refused() -> None:
    with pytest.raises(ingest.Reject):
        ingest._metadata_from_listing("o", "r", "garbage\n")
