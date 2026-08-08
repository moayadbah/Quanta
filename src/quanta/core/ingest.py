"""Secure repository ingestion — INGEST-01…10, §5.3.1.

This is the highest-risk path in the system: it takes a URL from an anonymous submitter
and fetches attacker-controlled bytes onto the host. Four threats are addressed by
construction rather than by mitigation (§7.3):

* **T1 SSRF.** :func:`parse_repo_url` validates scheme, host, userinfo, port, query and
  the owner/repo character class **before any network call happens**. That ordering is
  the control — a later check would already have leaked a DNS lookup.
* **T4 Command injection.** Every subprocess call is an argument vector with
  ``shell=False`` and a minimal environment, so neither a crafted repo name nor a user or
  system gitconfig can inject behaviour.
* **T2 Path traversal.** Symlinks are skipped unconditionally, files and directories
  alike, and every yielded path is re-checked for containment under the clone root.
* **T3 Resource exhaustion.** Size is checked against the GitHub API before cloning, and
  traversal runs under file-count, byte, per-file and depth budgets.

Nothing here imports, executes or installs target code, and nothing retains it — the
clone is deleted on every path including failure and timeout (INGEST-09).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict

from quanta.config import Settings, get_settings
from quanta.core.models import TruncationRecord
from quanta.errors import Reject, Truncated

#: INGEST-02. Deliberately narrow: no ``/``, no ``%``, no control characters, no unicode.
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

#: Budgets that stop the walk outright, as opposed to per-item limits that skip one entry.
GLOBAL_BUDGETS = frozenset({"max_files", "max_total_bytes"})

#: Pinned API host. Redirects are never followed off this host (§7.3 control 3).
GITHUB_API = "https://api.github.com"

_SOURCE_SUFFIXES = frozenset({".py", ".pyi"})


class RepoMetadata(BaseModel):
    """Answers obtained from the GitHub API *before* any bytes are cloned (INGEST-03)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    owner: str
    name: str
    default_branch: str
    commit_sha: str
    size_kb: int
    is_private: bool = False

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"


# ---------------------------------------------------------------------------------------
# INGEST-01/02 — URL validation, before any network call
# ---------------------------------------------------------------------------------------


def parse_repo_url(raw: str, settings: Settings | None = None) -> tuple[str, str]:
    """Validate a public GitHub repository URL and return ``(owner, name)``.

    Raises :class:`~quanta.errors.Reject` with ``HOST_NOT_ALLOWED`` or ``URL_MALFORMED``.
    **No DNS resolution or outbound request occurs in this function** — that is the SSRF
    control, not an implementation detail.
    """
    cfg = settings or get_settings()

    if not isinstance(raw, str) or not raw:
        raise Reject("URL_MALFORMED", "empty URL")

    # Control characters and NUL never appear in a legitimate URL, and they are the
    # standard vehicle for splitting a value across a parser boundary. Reject on the raw
    # string, before urlparse gets a chance to normalise anything away.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        raise Reject("URL_MALFORMED", "URL contains control characters")

    # The accepted shape is exactly https://github.com/{owner}/{repo}. Checking for the
    # delimiters on the raw string rather than on urlparse's fields also catches the
    # empty forms ("...?" and "...#"), which parse to falsy values and would otherwise
    # slip past a `if u.query` test.
    if "?" in raw or "#" in raw:
        raise Reject("URL_MALFORMED", "query strings and fragments are not permitted")

    try:
        u = urlparse(raw)
    except ValueError as exc:
        raise Reject("URL_MALFORMED", f"unparseable URL: {exc}") from exc

    if u.scheme != "https":
        raise Reject("HOST_NOT_ALLOWED", f"scheme {u.scheme or '(none)'!r} is not https")

    try:
        hostname = u.hostname
    except ValueError as exc:
        raise Reject("URL_MALFORMED", f"invalid host: {exc}") from exc

    # Allowlist, not denylist. Loopback, link-local (169.254.169.254) and RFC1918 hosts
    # are excluded because they are not github.com, so no special-casing is needed.
    if hostname is None or hostname.lower() not in cfg.ingest.allowed_hosts:
        raise Reject("HOST_NOT_ALLOWED", f"host {hostname!r} is not in the allowlist")

    if u.username or u.password:
        raise Reject("URL_MALFORMED", "userinfo is not permitted")

    try:
        port = u.port
    except ValueError as exc:
        raise Reject("URL_MALFORMED", f"invalid port: {exc}") from exc
    if port is not None:
        raise Reject("URL_MALFORMED", "explicit ports are not permitted")

    if u.query or u.fragment or u.params:
        raise Reject("URL_MALFORMED", "query strings and fragments are not permitted")

    # Split without discarding empty segments: "o//r" must be rejected, not silently
    # collapsed into a valid-looking pair.
    parts = u.path.strip("/").split("/")
    if len(parts) != 2 or not all(parts):
        raise Reject("URL_MALFORMED", "path must be exactly /{owner}/{repo}")

    owner, name = parts[0], parts[1].removesuffix(".git")
    if not (_REPO_RE.match(owner) and _REPO_RE.match(name)):
        raise Reject("URL_MALFORMED", "owner/repo contain characters outside [A-Za-z0-9._-]")

    # "." and ".." satisfy the character class above but are path traversal primitives.
    # They must never reach a filesystem join or a git argument.
    if owner in {".", ".."} or name in {".", ".."}:
        raise Reject("URL_MALFORMED", "owner/repo may not be a relative path segment")

    return owner, name


# ---------------------------------------------------------------------------------------
# INGEST-03 — metadata resolution before cloning
# ---------------------------------------------------------------------------------------


def resolve_metadata(
    owner: str,
    name: str,
    settings: Settings | None = None,
    client: httpx.Client | None = None,
) -> RepoMetadata:
    """Resolve existence, visibility, size and head SHA via the GitHub REST API.

    Rejecting here is cheap: a private, missing or oversized repository costs one HTTPS
    round trip instead of a clone.
    """
    cfg = settings or get_settings()
    owned = client is None
    http = client or httpx.Client(
        timeout=30.0,
        # Never follow a redirect: a 302 to another host would be an SSRF bypass that
        # application-level host checks could not see (§7.3 control 3, §11.2).
        follow_redirects=False,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "quanta"},
    )
    try:
        repo = _get_json(http, f"{GITHUB_API}/repos/{owner}/{name}")

        if repo.get("private", False):
            raise Reject("REPO_PRIVATE", "repository is not public")

        raw_size = repo.get("size", 0)
        size_kb = int(raw_size) if isinstance(raw_size, int | float | str) else 0
        if size_kb > cfg.ingest.max_repo_kb:
            raise Reject(
                "REPO_TOO_LARGE",
                f"Repository size {size_kb} KB exceeds limit {cfg.ingest.max_repo_kb} KB",
            )

        default_branch = str(repo["default_branch"])
        commit = _get_json(http, f"{GITHUB_API}/repos/{owner}/{name}/commits/{default_branch}")
        commit_sha = str(commit["sha"])

        return RepoMetadata(
            owner=owner,
            name=name,
            default_branch=default_branch,
            commit_sha=commit_sha,
            size_kb=size_kb,
            is_private=False,
        )
    finally:
        if owned:
            http.close()


def _get_json(http: httpx.Client, url: str) -> dict[str, object]:
    try:
        resp = http.get(url)
    except httpx.HTTPError as exc:
        raise Reject("GITHUB_UNAVAILABLE", f"GitHub API request failed: {exc}") from exc

    if resp.status_code == 404:
        raise Reject("REPO_NOT_FOUND", "repository does not exist or is not public")
    if resp.status_code in (403, 429):
        raise Reject("RATE_LIMITED", "GitHub API rate limit reached")
    if resp.is_redirect:
        raise Reject("GITHUB_UNAVAILABLE", "unexpected redirect from the GitHub API")
    if resp.status_code >= 400:
        raise Reject("GITHUB_UNAVAILABLE", f"GitHub API returned {resp.status_code}")

    payload: dict[str, object] = resp.json()
    return payload


# ---------------------------------------------------------------------------------------
# INGEST-05/06 — cloning
# ---------------------------------------------------------------------------------------


#: Restricted PATH handed to git. CPython resolves ``args[0]`` against the *child's*
#: ``PATH`` (``os.get_exec_path(env)``), so pinning this also pins which binary runs.
_GIT_PATH = "/usr/bin:/bin"


def _git_binary() -> str:
    """Resolve ``git`` to an absolute path.

    Passing a bare name would leave executable resolution to whatever ``PATH`` happens to
    be in effect. Resolving against the restricted path first, and only then falling back
    to the ambient one, keeps the common case pinned without breaking hosts that install
    git elsewhere.
    """
    found = shutil.which("git", path=_GIT_PATH) or shutil.which("git")
    if found is None:
        raise Reject("CLONE_FAILED", "git executable not found")
    return found


def _git_env(dest: Path) -> dict[str, str]:
    """A minimal environment so no gitconfig or credential helper can inject behaviour."""
    return {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "HOME": str(dest),
        "PATH": _GIT_PATH,
        "LC_ALL": "C",
    }


def clone_pinned(
    owner: str,
    name: str,
    sha: str,
    dest: Path,
    settings: Settings | None = None,
) -> None:
    """Clone at depth 1 and verify the checkout matches the resolved SHA.

    Submodules are refused: a submodule URL is attacker-controlled and is an SSRF vector
    in its own right (INGEST-05). Hooks are disabled, since a hook would be
    attacker-supplied code executing on our host during checkout.
    """
    cfg = settings or get_settings()
    env = _git_env(dest)
    git = _git_binary()
    url = f"https://github.com/{owner}/{name}.git"

    try:
        subprocess.run(
            [
                git,
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "protocol.ext.allow=never",
                "clone",
                "--depth=1",
                "--single-branch",
                "--no-tags",
                "--no-recurse-submodules",
                "--",
                url,
                str(dest),
            ],
            env=env,
            shell=False,
            check=True,
            timeout=cfg.ingest.clone_timeout_s,
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise Reject("CLONE_TIMEOUT", f"clone exceeded {cfg.ingest.clone_timeout_s}s") from exc
    except subprocess.CalledProcessError as exc:
        # stderr may echo repository-controlled text; it is never surfaced to the client.
        raise Reject("CLONE_FAILED", "git clone failed") from exc

    head = subprocess.run(
        [git, "-C", str(dest), "rev-parse", "HEAD"],
        env=env,
        shell=False,
        capture_output=True,
        text=True,
        check=True,
        stdin=subprocess.DEVNULL,
    ).stdout.strip()

    if head != sha:
        # The branch moved between resolve and clone. Aborting is the only honest option:
        # continuing would analyse different code than the provenance triple claims.
        raise Reject("SHA_MISMATCH", "branch moved between metadata resolution and clone")


def _force_writable(root: Path) -> None:
    """Make every directory under ``root`` writable so its entries can be unlinked."""
    for dirpath, dirnames, _filenames in os.walk(root, topdown=False, followlinks=False):
        for name in dirnames:
            with suppress(OSError):
                (Path(dirpath) / name).chmod(0o700)
    with suppress(OSError):
        root.chmod(0o700)


def remove_tree(path: Path) -> None:
    """Delete a tree, defeating read-only directories, and never raise.

    ``rmtree(ignore_errors=True)`` alone is **not** sufficient: a directory without the
    write bit cannot have its entries unlinked, so the tree survives and the call reports
    nothing. That would silently retain third-party source, which INGEST-09 forbids
    unconditionally — and "unconditionally" is the whole point, since this runs on failure
    and timeout paths too.

    Errors are swallowed rather than raised: this always executes in a ``finally``, where
    an exception would mask the original failure.
    """
    if not path.exists():
        return
    shutil.rmtree(path, ignore_errors=True)
    if not path.exists():
        return

    # Something refused to go. Repair permissions bottom-up and try once more.
    _force_writable(path)
    shutil.rmtree(path, ignore_errors=True)


@contextmanager
def scratch_dir(prefix: str = "quanta-") -> Iterator[Path]:
    """An ephemeral clone directory, removed **unconditionally** at exit (INGEST-06/09).

    Third-party source is never retained. Besides being the stated data-handling rule,
    this removes the copyleft redistribution question entirely, and it keeps committer
    names and email addresses — personal data under GDPR and the PDPL — off the host.
    """
    path = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield path
    finally:
        remove_tree(path)


# ---------------------------------------------------------------------------------------
# INGEST-07/08 — safe traversal
# ---------------------------------------------------------------------------------------


@dataclass
class WalkResult:
    """Files to analyse plus every budget that was hit, as *declared* truncations."""

    files: list[Path] = field(default_factory=list)
    truncations: list[TruncationRecord] = field(default_factory=list)
    total_bytes: int = 0

    @property
    def truncated(self) -> bool:
        return bool(self.truncations)

    @property
    def hit_global_budget(self) -> bool:
        return any(t.reason in GLOBAL_BUDGETS for t in self.truncations)

    def _declare(self, reason: str, limit: int, observed: int) -> None:
        """Record a truncation once per reason — the report needs the fact, not a tally."""
        if not any(t.reason == reason for t in self.truncations):
            self.truncations.append(TruncationRecord(reason=reason, limit=limit, observed=observed))


def _is_unsafe_name(name: str) -> bool:
    return "\x00" in name or any(ord(ch) < 0x20 for ch in name)


def walk_repository(root: Path, settings: Settings | None = None) -> WalkResult:
    """Enumerate analysable source files under ``root`` (PROC-01, INGEST-07/08).

    Traversal order is sorted, not ``readdir`` order, so the file list — and therefore
    every downstream artifact — is deterministic (NFR-03).

    Budget semantics, which differ deliberately from the sketch in §5.3.1: that sketch
    ``continue``\\ s past an oversized file, which is a *silent drop*. INGEST-08 requires
    a declared truncation instead, so every skipped file is recorded. Global budgets
    (file count, total bytes) stop the walk; per-item limits (oversized file, excessive
    depth) record and continue, because one vendored blob should not abort the analysis
    of an otherwise fine repository.

    This function never raises on a budget: it returns the files gathered so far together
    with the declared truncations, so partial work is never thrown away. Callers wanting
    the §5.3.1 raising contract use :func:`safe_walk`.
    """
    cfg = (settings or get_settings()).ingest
    root = root.resolve()
    result = WalkResult()
    deny = set(cfg.deny_dirs)
    stop = False

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if stop:
            break
        here = Path(dirpath)

        # Prune: denylisted directories, symlinked directories (loop + escape vector),
        # and anything with a hostile name. Sorted for determinism.
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in deny and not _is_unsafe_name(d) and not (here / d).is_symlink()
        )

        depth = len(here.relative_to(root).parts)
        if depth > cfg.max_depth:
            result._declare("max_depth", cfg.max_depth, depth)
            dirnames[:] = []
            continue

        for fn in sorted(filenames):
            if _is_unsafe_name(fn):
                continue

            p = here / fn
            if p.suffix not in _SOURCE_SUFFIXES:
                continue
            if p.is_symlink():  # traversal + loop vector; skipped unconditionally
                continue

            try:
                resolved = p.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_relative_to(root):  # containment, belt and braces
                continue

            try:
                size = p.stat().st_size
            except OSError:
                continue

            if size > cfg.max_file_bytes:
                result._declare("max_file_bytes", cfg.max_file_bytes, size)
                continue

            if len(result.files) >= cfg.max_files:
                result._declare("max_files", cfg.max_files, len(result.files) + 1)
                stop = True
                break

            if result.total_bytes + size > cfg.max_total_bytes:
                result._declare("max_total_bytes", cfg.max_total_bytes, result.total_bytes + size)
                stop = True
                break

            result.files.append(p)
            result.total_bytes += size

    result.files.sort()
    return result


def safe_walk(root: Path, settings: Settings | None = None) -> Iterator[Path]:
    """Generator form of :func:`walk_repository`, matching the §5.3.1 contract.

    Yields every file gathered, then raises :class:`~quanta.errors.Truncated` if a global
    budget was exhausted. Consumers therefore keep the partial corpus *and* learn that it
    is partial — the distinction INGEST-08 exists to preserve.
    """
    result = walk_repository(root, settings)
    yield from result.files
    if result.hit_global_budget:
        hit = next(t for t in result.truncations if t.reason in GLOBAL_BUDGETS)
        raise Truncated(hit.reason, hit.limit, hit.observed)
