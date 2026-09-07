"""Per-job Linux limits and a kernel-enforced network cutoff after acquisition.

Native macOS/Windows runs retain a watchdog but cannot provide these Linux controls.
The Compose worker requires the controls and refuses jobs if they cannot be installed.
"""

from __future__ import annotations

import ctypes
import errno
import os
import signal
import sys
from typing import Any

from quanta.config import Settings
from quanta.errors import Reject


def prepare(cfg: Settings) -> None:
    if os.name == "posix" and os.getpgrp() != os.getpid():
        os.setsid()
    # Do not give the parser process inherited service tokens or user configuration.
    allowed = {"PATH", "LANG", "LC_ALL", "SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP"}
    environment = {k: v for k, v in os.environ.items() if k in allowed}
    os.environ.clear()
    os.environ.update(environment)
    if sys.platform != "linux":
        if cfg.require_sandbox:
            raise Reject("SANDBOX_UNAVAILABLE", "the hardened worker requires Linux")
        return
    import resource

    for kind, limit in (
        (resource.RLIMIT_AS, 2 * 1024**3),
        (resource.RLIMIT_CPU, cfg.analysis.max_job_seconds),
        (resource.RLIMIT_NOFILE, 128),
        (resource.RLIMIT_FSIZE, cfg.ingest.max_total_bytes),
        (resource.RLIMIT_NPROC, 128),
    ):
        _, hard = resource.getrlimit(kind)
        limit = min(limit, hard) if hard != resource.RLIM_INFINITY else limit
        resource.setrlimit(kind, (limit, limit))
    libc = ctypes.CDLL(None, use_errno=True)
    # PR_SET_NO_NEW_PRIVS; inherited by all descendants.
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise Reject("SANDBOX_UNAVAILABLE", "cannot disable privilege escalation")
    # A worker crash must not leave a long-running analyzer behind.
    parent = os.getppid()
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        raise Reject("SANDBOX_UNAVAILABLE", "cannot bind analyzer lifetime to worker")
    if cfg.require_sandbox and os.getuid() == 0:
        raise Reject("SANDBOX_UNAVAILABLE", "the hardened worker must run as a non-root user")


def block_network(*, required: bool) -> None:
    """Install a libseccomp filter; no Python socket monkeypatch can undo it."""
    if sys.platform != "linux":
        if required:
            raise Reject("SANDBOX_UNAVAILABLE", "network isolation requires Linux")
        return
    try:
        lib: Any = ctypes.CDLL("libseccomp.so.2", use_errno=True)
        lib.seccomp_init.argtypes = [ctypes.c_uint32]
        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
        lib.seccomp_rule_add.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint,
        ]
        lib.seccomp_load.argtypes = [ctypes.c_void_p]
        lib.seccomp_release.argtypes = [ctypes.c_void_p]
        context = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
        if not context:
            raise OSError("cannot allocate seccomp filter")
        try:
            for name in (
                b"socket",
                b"socketpair",
                b"connect",
                b"sendto",
                b"sendmsg",
                b"sendmmsg",
                b"io_uring_setup",
            ):
                syscall = lib.seccomp_syscall_resolve_name(name)
                if (
                    syscall >= 0
                    and lib.seccomp_rule_add(
                        context,
                        0x00050000 | errno.EPERM,
                        syscall,
                        0,
                    )
                    != 0
                ):
                    raise OSError("cannot add network rule")
            if lib.seccomp_load(context) != 0:
                raise OSError("cannot install seccomp filter")
        finally:
            lib.seccomp_release(context)
    except (OSError, AttributeError) as exc:
        if required:
            raise Reject("SANDBOX_UNAVAILABLE", "kernel network cutoff unavailable") from exc
