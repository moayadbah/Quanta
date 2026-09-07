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
            subprocess.CompletedProcess([], 0, stdout=sha + "\n"),
        ]
        ingest.clone_pinned("owner", "repo", sha, tmp_path / "repo", cfg)
    clone = run.call_args_list[0]
    assert f"http.proxy={proxy or ''}" in clone.args[0]
    assert all("proxy" not in name.lower() for name in clone.kwargs["env"])
    assert "secret" not in str(clone)
