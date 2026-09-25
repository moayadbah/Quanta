"""Run a repository's own tests in a network-isolated container (Master Plan 10.2, 10.4).

This is the only place in Quanta that executes repository code, and only on request.
Installation has network access (it has to reach PyPI); every test run has none. Each run
starts from the frozen post-install image, so no state leaks between runs.

Controls on every test run: ``--network none``, ``--cap-drop ALL``,
``--security-opt no-new-privileges``, a process limit, a memory limit, a CPU limit and a
wall-clock timeout after which the container is killed. The repository is mounted
read-only and copied inside, so a test cannot change the analysed tree.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The round-two harness image, pinned by digest (evidence/harness/image-digest.txt).
BASE_IMAGE = (
    "python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9"
)
LIMITS = [
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--pids-limit",
    "512",
    "--memory",
    "4g",
    "--cpus",
    "2",
]
PLUGIN_DIR = Path(__file__).resolve().parent
_SAFE = re.compile(r"[^a-z0-9_.-]")


def slug(name: str) -> str:
    """Docker image and container names must be lowercase and simple."""
    return _SAFE.sub("-", name.lower())[:60] or "repo"


def docker_available() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    try:
        probe = subprocess.run(
            [docker, "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _docker() -> str:
    found = shutil.which("docker")
    if found is None:
        raise RuntimeError("docker is not installed")
    return found


def _run(argv: list[str], timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


@dataclass
class RunRecord:
    name: str
    exit: int | str
    seconds: float
    junit: Path
    trace: Path | None
    log_tail: str

    def public(self) -> dict[str, Any]:
        return {"run": self.name, "exit": self.exit, "seconds": self.seconds}


class Sandbox:
    """One repository's frozen test environment."""

    def __init__(self, name: str, source: Path, out: Path) -> None:
        self.name = slug(name)
        self.source = source.resolve()
        self.out = out.resolve()
        self.out.mkdir(parents=True, exist_ok=True)
        self.image = f"quanta-verify-{self.name}:base"

    def install(self, command: str, timeout: int = 1200) -> tuple[bool, str]:
        """Copy the tree, install with network, freeze the result as an image."""
        docker = _docker()
        container = f"quanta-install-{self.name}"
        _run([docker, "rm", "-f", container])
        script = (
            "cp -r /mnt/src /work && cd /work && pip install -q uv && "
            + command
            + " && uv pip install --system -q coverage"
            + " && (python -c 'import pytest' || uv pip install --system -q pytest)"
            + " && uv pip freeze --system > /freeze.txt"
        )
        try:
            result = _run(
                [
                    docker,
                    "run",
                    "--name",
                    container,
                    *LIMITS,
                    "-v",
                    f"{self.source}:/mnt/src:ro",
                    BASE_IMAGE,
                    "sh",
                    "-c",
                    script,
                ],
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            _run([docker, "rm", "-f", container])
            return False, "installation exceeded its time limit"
        tail = (result.stdout[-1500:] + result.stderr[-1500:]).strip()
        if result.returncode != 0:
            _run([docker, "rm", "-f", container])
            return False, tail
        _run([docker, "commit", container, self.image])
        freeze = _run([docker, "run", "--rm", self.image, "cat", "/freeze.txt"]).stdout
        (self.out / "freeze.txt").write_text(freeze, encoding="utf-8", newline="\n")
        _run([docker, "rm", "-f", container])
        return True, tail

    def run_tests(
        self,
        name: str,
        *,
        overlay: Path | None = None,
        trace: bool = False,
        coverage_files: list[str] | None = None,
        pytest_args: list[str] | None = None,
        timeout: int = 900,
    ) -> RunRecord:
        """One pytest run with no network. ``overlay`` files replace their originals."""
        docker = _docker()
        mounts = ["-v", f"{self.out}:/out"]
        prep = ""
        if overlay is not None:
            mounts += ["-v", f"{overlay.resolve()}:/overlay:ro"]
            prep = "cp -r /overlay/. /work/ && "
        env = ["-e", "PYTHONHASHSEED=0", "-e", "PYTHONDONTWRITEBYTECODE=1"]
        plugin = ""
        trace_path: Path | None = None
        if trace:
            mounts += ["-v", f"{PLUGIN_DIR}:/quanta-plugin:ro"]
            env += [
                "-e",
                "PYTHONPATH=/quanta-plugin",
                "-e",
                f"QUANTA_TRACE_OUT=/out/trace-{name}.jsonl",
                "-e",
                "QUANTA_TRACE_ROOT=/work",
            ]
            plugin = "-p trace_plugin "
            trace_path = self.out / f"trace-{name}.jsonl"
        extra = " ".join(pytest_args or [])
        base = (
            f"-p no:cacheprovider -p no:randomly -q --continue-on-collection-errors {plugin}"
            f"--junitxml=/out/junit-{name}.xml {extra}"
        )
        if coverage_files:
            include = ",".join(coverage_files)
            test = (
                "printf '[run]\\ndata_file = /tmp/.cov\\n' > /tmp/covrc; "
                f"python -m coverage run --rcfile=/tmp/covrc --include={include} -m pytest {base}; "
                "rc=$?; python -m coverage json --rcfile=/tmp/covrc "
                f"-o /out/coverage-{name}.json; exit $rc"
            )
        else:
            test = f"python -m pytest {base}"
        container = f"quanta-run-{self.name}-{slug(name)}"
        _run([docker, "rm", "-f", container])
        started = time.monotonic()
        try:
            result = _run(
                [
                    docker,
                    "run",
                    "--rm",
                    "--name",
                    container,
                    "--network",
                    "none",
                    *LIMITS,
                    *env,
                    *mounts,
                    "-w",
                    "/work",
                    self.image,
                    "sh",
                    "-c",
                    prep + test,
                ],
                timeout=timeout,
            )
            code: int | str = result.returncode
            tail = (result.stdout[-2000:] + result.stderr[-1000:]).strip()
        except subprocess.TimeoutExpired:
            _run([docker, "kill", container])
            code, tail = "timeout", ""
        record = RunRecord(
            name=name,
            exit=code,
            seconds=round(time.monotonic() - started, 1),
            junit=self.out / f"junit-{name}.xml",
            trace=trace_path,
            log_tail=tail,
        )
        (self.out / f"log-{name}.txt").write_text(tail, encoding="utf-8", newline="\n")
        return record


def outcomes(junit: Path) -> dict[str, str]:
    """Test id -> ``passed``, ``failed`` or ``skipped`` from a junit file we wrote."""
    result: dict[str, str] = {}
    if not junit.is_file():
        return result
    root = ET.parse(junit).getroot()  # noqa: S314 - our own pytest junit output
    for case in root.iter("testcase"):
        test_id = f"{case.get('classname')}::{case.get('name')}"
        tags = {child.tag for child in case}
        result[test_id] = (
            "failed"
            if tags & {"failure", "error"}
            else "skipped"
            if "skipped" in tags
            else "passed"
        )
    return result


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
