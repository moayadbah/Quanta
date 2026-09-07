"""Small, reviewable hash upgrades. Target code is parsed, never executed.

These are compatibility-changing proposals, not automatic security conclusions.
Protocol migrations and key changes deliberately have no generated patch.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

import libcst as cst
from libcst.codemod import CodemodContext
from libcst.codemod.visitors import AddImportsVisitor
from libcst.metadata import MetadataWrapper, PositionProvider, QualifiedNameProvider
from pydantic import BaseModel, ConfigDict, Field

from quanta.config import ProductSettings
from quanta.errors import Reject

HASH_NOTE = (
    "SHA-256 changes digest values and length. Check stored hashes, signatures, "
    "protocols, fixtures and consumers before merging. It is not a password hashing scheme."
)


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    rule: str
    line: int
    start: int
    end: int
    before: str
    after: str
    import_module: str = ""
    import_name: str = ""
    import_alias: str = ""
    note: str = HASH_NOTE


class FixFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    path: str
    source: str
    sha256: str
    changes: list[Change]


class FixPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: int = 1
    files: list[FixFile] = Field(default_factory=list)
    limited: bool = False

    def public(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "limited": self.limited,
            "files": [
                {
                    "path": f.path,
                    "changes": [
                        c.model_dump(
                            exclude={"start", "end", "import_module", "import_name", "import_alias"}
                        )
                        for c in f.changes
                    ],
                }
                for f in self.files
            ],
            "validation": "Python syntax checked. Repository tests were not run.",
            "scope": "Hash upgrades only. Key, certificate and protocol migrations need review.",
        }


def safe_path(path: str) -> bool:
    parsed = PurePosixPath(path)
    return (
        not parsed.is_absolute()
        and str(parsed) == path
        and len(path) < 500
        and path.endswith(".py")
        and "\\" not in path
        and all(not part.startswith(".") for part in parsed.parts)
        and not any(ord(char) < 32 for char in path)
    )


class Proposals(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (QualifiedNameProvider, PositionProvider)

    def __init__(self, source: str, path: str) -> None:
        self.source, self.path = source, path
        self.lines = source.splitlines(keepends=True)
        self.changes: list[Change] = []
        self.alias = "_quanta_sha256"
        while self.alias in source:
            self.alias += "_"

    def add(
        self, node: cst.CSTNode, replacement: str, rule: str, module: str = "", name: str = ""
    ) -> None:
        position = self.get_metadata(PositionProvider, node)
        start = sum(map(len, self.lines[: position.start.line - 1])) + position.start.column
        end = sum(map(len, self.lines[: position.end.line - 1])) + position.end.column
        identity = hashlib.sha256(f"{self.path}:{start}:{rule}".encode()).hexdigest()[:24]
        self.changes.append(
            Change(
                id=identity,
                rule=rule,
                line=position.start.line,
                start=start,
                end=end,
                before=self.source[start:end],
                after=replacement,
                import_module=module,
                import_name=name,
                import_alias=self.alias if module else "",
            )
        )

    def visit_Call(self, node: cst.Call) -> None:  # noqa: N802
        if len(self.changes) >= 200:
            return
        names = self.get_metadata(QualifiedNameProvider, node.func, set())
        if len(names) != 1:
            return
        qualified = next(iter(names))
        if qualified.source.name != "IMPORT":
            return
        if any(
            arg.keyword
            and arg.keyword.value == "usedforsecurity"
            and isinstance(arg.value, cst.Name)
            and arg.value.value == "False"
            for arg in node.args
        ):
            return
        targets = {
            "hashlib.md5": ("hashlib", "sha256"),
            "hashlib.sha1": ("hashlib", "sha256"),
            "cryptography.hazmat.primitives.hashes.MD5": (
                "cryptography.hazmat.primitives.hashes",
                "SHA256",
            ),
            "cryptography.hazmat.primitives.hashes.SHA1": (
                "cryptography.hazmat.primitives.hashes",
                "SHA256",
            ),
        }
        if qualified.name in targets:
            module, name = targets[qualified.name]
            if isinstance(node.func, cst.Attribute):
                self.add(node.func.attr, name, "weak-hash-to-sha256")
            elif isinstance(node.func, cst.Name):
                alias = self.alias
                self.alias += "_" + name
                while self.alias in self.source:
                    self.alias += "_"
                self.add(node.func, self.alias, "weak-hash-to-sha256", module, name)
                self.alias = alias
        elif qualified.name == "hashlib.new":
            for index, arg in enumerate(node.args):
                if (index == 0 and not arg.keyword) or (
                    arg.keyword and arg.keyword.value == "name"
                ):
                    if isinstance(arg.value, cst.SimpleString):
                        value = arg.value.evaluated_value
                        if isinstance(value, str) and value.lower() in {"md5", "sha1", "sha-1"}:
                            self.add(arg.value, '"sha256"', "weak-hash-to-sha256")
                    break


def propose(source: str, path: str) -> FixFile | None:
    if not safe_path(path):
        return None
    visitor = Proposals(source, path)
    try:
        MetadataWrapper(cst.parse_module(source)).visit(visitor)
    except (cst.ParserSyntaxError, cst.CSTValidationError, RecursionError):
        return None
    if not visitor.changes:
        return None
    return FixFile(
        path=path,
        source=source,
        sha256=hashlib.sha256(source.encode()).hexdigest(),
        changes=visitor.changes,
    )


def propose_repository(root: Path, files: list[Path], settings: ProductSettings) -> FixPlan:
    results: list[FixFile] = []
    retained = 0
    limited = False
    for path in files:
        if len(results) >= settings.max_fix_files:
            limited = True
            break
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            continue
        if path.stat().st_size > min(settings.max_fix_bytes - retained, 100_000):
            limited = True
            continue
        try:
            source = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeError):
            continue
        result = propose(source, path.relative_to(root).as_posix())
        if result:
            results.append(result)
            retained += len(source.encode())
    return FixPlan(files=results, limited=limited)


def review(plan: FixPlan, selected: list[str]) -> dict[str, Any]:
    chosen = set(selected)
    known = {change.id for file in plan.files for change in file.changes}
    if not chosen or len(chosen) != len(selected) or not chosen.issubset(known):
        raise Reject("FIX_UNAVAILABLE", "Select one or more available fixes.")
    output: list[dict[str, str]] = []
    for file in plan.files:
        changes = [change for change in file.changes if change.id in chosen]
        if not changes:
            continue
        if (
            not safe_path(file.path)
            or hashlib.sha256(file.source.encode()).hexdigest() != file.sha256
        ):
            raise Reject("REVIEW_STALE", "The stored proposal could not be verified. Scan again.")
        updated = file.source
        boundary = len(updated)
        for change in sorted(changes, key=lambda c: c.start, reverse=True):
            if (
                change.start < 0
                or change.end > boundary
                or updated[change.start : change.end] != change.before
            ):
                raise Reject("REVIEW_STALE", "Conflicting proposals. Scan again.")
            updated = updated[: change.start] + change.after + updated[change.end :]
            boundary = change.start
        try:
            context = CodemodContext()
            for change in changes:
                if change.import_module:
                    AddImportsVisitor.add_needed_import(
                        context,
                        change.import_module,
                        change.import_name,
                        asname=change.import_alias,
                    )
            updated = AddImportsVisitor(context).transform_module(cst.parse_module(updated)).code
            ast.parse(updated, filename=file.path)
        except (SyntaxError, cst.ParserSyntaxError, cst.CSTValidationError) as exc:
            raise Reject(
                "FIX_UNAVAILABLE", "The selected changes did not pass syntax validation."
            ) from exc
        diff = "".join(
            difflib.unified_diff(
                file.source.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile="a/" + file.path,
                tofile="b/" + file.path,
            )
        )
        output.append(
            {"path": file.path, "content": updated, "before_sha256": file.sha256, "diff": diff}
        )
    digest = hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest()
    return {
        "digest": digest,
        "files": output,
        "selected": sorted(chosen),
        "validation": "Python syntax checked. Repository tests were not run.",
        "compatibility": HASH_NOTE,
    }
