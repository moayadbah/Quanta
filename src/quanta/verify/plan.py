"""How to install a repository for its tests (Master Plan 10.3).

First match wins. Rule 7 was added after round two: on pyjwt the ``tests`` extra alone did
not install ``cryptography``, so the RSA and EC tests were skipped and a verification
would have proved nothing about the cryptography it touched.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Distributions whose presence in an optional extra marks it as a crypto extra (rule 7).
CRYPTO_DISTRIBUTIONS = frozenset(
    {
        "cryptography",
        "pycryptodome",
        "pycryptodomex",
        "pynacl",
        "pyopenssl",
        "ecdsa",
        "rsa",
        "bcrypt",
        "argon2-cffi",
    }
)

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


@dataclass
class InstallPlan:
    command: str | None
    rule: str
    extras: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def possible(self) -> bool:
        return self.command is not None


def _requirement_names(requirements: list[Any]) -> set[str]:
    names = set()
    for requirement in requirements:
        match = _REQ_NAME.match(str(requirement))
        if match:
            names.add(match.group(1).lower().replace("_", "-"))
    return names


def install_plan(root: Path) -> InstallPlan:
    """Choose the install command for ``root`` (paths are shell-quoted by construction)."""
    pyproject = root / "pyproject.toml"
    data: dict[str, Any] = {}
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            data = {}
    requires = data.get("project", {}).get("requires-python")
    if requires:
        try:
            from packaging.specifiers import InvalidSpecifier, SpecifierSet

            if not SpecifierSet(str(requires)).contains("3.12"):
                return InstallPlan(None, "PYTHON_VERSION", reason=f"requires-python {requires}")
        except (ImportError, InvalidSpecifier):
            pass

    extras_table = data.get("project", {}).get("optional-dependencies", {}) or {}
    crypto_extras = sorted(
        key
        for key, reqs in extras_table.items()
        if isinstance(reqs, list) and _requirement_names(reqs) & CRYPTO_DISTRIBUTIONS
    )
    for key in ("test", "tests", "testing", "dev"):
        if key in extras_table:
            chosen = [key, *[e for e in crypto_extras if e != key]]
            return InstallPlan(
                f"uv pip install --system -e '.[{','.join(chosen)}]'", f"rule2:{key}", chosen
            )
    groups = data.get("dependency-groups", {}) or {}
    suffix = f"'.[{','.join(crypto_extras)}]'" if crypto_extras else "."
    for key in ("test", "tests", "dev"):
        if key in groups:
            return InstallPlan(
                f"uv pip install --system -e {suffix} --group {key}", f"rule3:{key}", crypto_extras
            )
    patterns = (
        "requirements-test*.txt",
        "requirements-dev*.txt",
        "test-requirements*.txt",
        "requirements/test*.txt",
    )
    reqs = sorted({p.relative_to(root).as_posix() for pat in patterns for p in root.glob(pat)})
    packaged = pyproject.is_file() or (root / "setup.py").is_file()
    if reqs:
        safe = [r for r in reqs if re.fullmatch(r"[A-Za-z0-9._/-]+", r)]
        command = "uv pip install --system " + " ".join(f"-r {r}" for r in safe)
        return InstallPlan(command + (f" -e {suffix}" if packaged else ""), "rule4", crypto_extras)
    if packaged:
        return InstallPlan(f"uv pip install --system -e {suffix}", "rule5", crypto_extras)
    return InstallPlan(
        None, "NO_INSTALL_METHOD", reason="no pyproject.toml, setup.py or requirements"
    )
