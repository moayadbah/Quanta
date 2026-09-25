"""Small, reviewable hash upgrades (pattern P0). Target code is parsed, never executed.

These are compatibility-changing proposals, not automatic security conclusions. Round two
ran P0 through each project's own tests and it regressed both real projects it touched
(Master Plan 22.4): HTTP Digest login in requests v2.31.0, where the server chooses the
algorithm, and signatures in itsdangerous, where SHA-1 is the stored default. Two guards,
pre-registered in ``evidence/PROTOCOL-R3.md`` (K1), now refuse those shapes, and every
refusal is recorded with its reason instead of disappearing:

* ``PROTOCOL_NEGOTIATED`` (Master Plan 9.2): the enclosing function, or any function
  enclosing it, or the module body for module-level calls, compares a value with a string
  naming the same algorithm (``if algorithm == "MD5":``). A peer or a stored format
  chooses the hash, so changing it breaks interoperability.
* ``STORED_FORMAT_DEFAULT``: the hash is used as a digest method: it sits in a function
  that the module uses as a value (``default_digest_method = staticmethod(_lazy_sha1)``),
  or it is a default argument value. Its output is persisted or verified later, so
  changing it silently invalidates existing data.

Anything that passes is still **unverified** until the project's tests have run on it.
Protocol migrations and key changes deliberately have no generated patch.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

import libcst as cst
from libcst.codemod import CodemodContext
from libcst.codemod.visitors import AddImportsVisitor
from libcst.metadata import (
    MetadataWrapper,
    ParentNodeProvider,
    PositionProvider,
    QualifiedNameProvider,
    ScopeProvider,
)
from pydantic import BaseModel, ConfigDict, Field

from quanta.config import ProductSettings
from quanta.core.roles import classify_role
from quanta.core.ruleset_v2 import canonical
from quanta.errors import Reject

HASH_NOTE = (
    "SHA-256 changes digest values and length. Check stored hashes, signatures, "
    "protocols, fixtures and consumers before merging. It is not a password hashing scheme."
)


class Edit(BaseModel):
    """A second span that must change together with a change (a local import)."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    start: int
    end: int
    before: str
    after: str


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
    #: Edits applied together with this one (the import that binds a renamed call).
    extra: tuple[Edit, ...] = ()
    #: The whole source line before and after, built from the exact offsets. What the
    #: page shows; never reconstructed by searching the line for text.
    line_before: str = ""
    line_after: str = ""


class Skipped(BaseModel):
    """A candidate Quanta considered and refused to change, with the reason (Master Plan 9.8)."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    path: str
    line: int
    rule: str
    code: str
    detail: str
    evidence_line: int = 0


class FixFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    path: str
    source: str
    sha256: str
    changes: list[Change]


class GuideSite(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    finding_id: str
    path: str
    line: int
    name: str = ""
    algorithm: str = ""
    role: str = "source"


class Guide(BaseModel):
    """A guided migration: no automatic patch is safe, so the page shows the target, real
    example code and the sites it applies to (round five, ``core/coverage.py``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    sites: list[GuideSite] = Field(default_factory=list)


class FixPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: int = 1
    files: list[FixFile] = Field(default_factory=list)
    limited: bool = False
    skipped: list[Skipped] = Field(default_factory=list)
    guides: list[Guide] = Field(default_factory=list)

    def public(self) -> dict[str, Any]:
        from quanta.core.coverage import migrations

        catalogue = migrations()
        return {
            "version": self.version,
            "limited": self.limited,
            "skipped": [s.model_dump() for s in self.skipped],
            "guides": [
                {
                    **g.model_dump(),
                    "to": catalogue.get(g.id, {}).get("to", ""),
                    "example": catalogue.get(g.id, {}).get("example", ""),
                    "sources": catalogue.get(g.id, {}).get("sources", []),
                }
                for g in self.guides
            ],
            "verified": False,
            "files": [
                {
                    "path": f.path,
                    "changes": [
                        {
                            **c.model_dump(
                                exclude={
                                    "start",
                                    "end",
                                    "import_module",
                                    "import_name",
                                    "import_alias",
                                    "extra",
                                }
                            ),
                            **_context(f.source, c.line),
                        }
                        for c in f.changes
                    ],
                }
                for f in self.files
            ],
            "validation": (
                "Python syntax checked. Not verified: repository tests have not run on this "
                "change. In round two this fix broke tests in 2 of 2 real projects it touched."
            ),
            "scope": "Hash upgrades only. Key, certificate and protocol migrations need review.",
        }


#: Unchanged lines shown on each side of a patch, as in a code review.
CONTEXT_LINES = 2


def _context(source: str, line: int) -> dict[str, Any]:
    lines = source.splitlines()
    index = line - 1
    if not 0 <= index < len(lines):
        return {"context_before": [], "context_after": [], "context_start": line}
    start = max(0, index - CONTEXT_LINES)
    return {
        "context_before": lines[start:index],
        "context_after": lines[index + 1 : index + 1 + CONTEXT_LINES],
        "context_start": start + 1,
    }


def is_current(plan: FixPlan) -> bool:
    """True when every change carries the line preview this engine writes."""
    return all(c.line_before for f in plan.files for c in f.changes)


def reevaluate(plan: FixPlan) -> FixPlan:
    """Re-derive an older plan's patches with today's rules, from the source it retained.

    An engine before round five proposed changes the current rules refuse (test fixtures,
    known-answer tests) and wrote generated names (``_quanta_sha256_sha256``). Such a plan
    is never shown as it was: each retained file is proposed again, so a change the current
    rules refuse can only appear as a refusal. A file whose source no longer matches its
    recorded hash contributes nothing.
    """
    if is_current(plan):
        return plan
    files: list[FixFile] = []
    skipped: list[Skipped] = []
    reviewed: set[str] = set()
    for file in plan.files:
        reviewed.add(file.path)
        if hashlib.sha256(file.source.encode()).hexdigest() != file.sha256:
            continue
        result, refused = propose_with_skips(file.source, file.path)
        skipped.extend(refused)
        if result is not None:
            files.append(result)
    skipped += [s for s in plan.skipped if s.path not in reviewed]
    return FixPlan(files=files, limited=plan.limited, skipped=skipped[:200], guides=plan.guides)


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


#: Cheap text gate before the metadata parse (propose_repository).
_WEAK_HASH_TEXT = re.compile(r"md5|sha-?1", re.IGNORECASE)

_CANDIDATE_ALGORITHM = {
    "hashlib.md5": "MD5",
    "hashlib.sha1": "SHA1",
    "cryptography.hazmat.primitives.hashes.MD5": "MD5",
    "cryptography.hazmat.primitives.hashes.SHA1": "SHA1",
}


class _GuardFacts(cst.CSTVisitor):
    """First pass: what the guards need to know about the whole module."""

    def __init__(self) -> None:
        #: id(FunctionDef) or 0 for module level -> {canonical algorithm: comparison line}
        self.compared: dict[int, dict[str, int]] = {}
        #: id(FunctionDef) or 0 -> algorithms referenced as a value, not called
        #: (``hash_func=hashlib.sha1``). A call changed beside it would leave the two
        #: out of step.
        self.value_refs: dict[int, set[str]] = {}
        self.module_functions: set[str] = set()
        self._functions: list[cst.FunctionDef] = []
        self._depth = 0
        self._callees: set[int] = set()

    def visit_Call(self, node: cst.Call) -> None:
        self._callees.add(id(node.func))

    def visit_Attribute(self, node: cst.Attribute) -> None:
        if id(node) in self._callees:
            return
        if (
            isinstance(node.value, cst.Name)
            and node.value.value == "hashlib"
            and node.attr.value in {"md5", "sha1"}
        ):
            key = id(self._functions[-1]) if self._functions else 0
            self.value_refs.setdefault(key, set()).add(node.attr.value.upper())

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        if not self._functions and self._depth == 0:
            self.module_functions.add(node.name.value)
        self._functions.append(node)

    def leave_FunctionDef(self, original_node: cst.FunctionDef) -> None:
        self._functions.pop()

    def visit_ClassDef(self, node: cst.ClassDef) -> None:
        self._depth += 1

    def leave_ClassDef(self, original_node: cst.ClassDef) -> None:
        self._depth -= 1

    def visit_Comparison(self, node: cst.Comparison) -> None:
        operands = [node.left] + [t.comparator for t in node.comparisons]
        ops = [t.operator for t in node.comparisons]
        if not any(isinstance(o, (cst.Equal, cst.NotEqual, cst.In, cst.NotIn)) for o in ops):
            return
        key = id(self._functions[-1]) if self._functions else 0
        for operand in operands:
            for value in _strings(operand):
                algo = canonical(value)
                if algo in {"MD5", "SHA1"}:
                    self.compared.setdefault(key, {})[algo] = 0


def _strings(node: cst.CSTNode) -> list[str]:
    if isinstance(node, cst.SimpleString):
        value = node.evaluated_value
        return [value] if isinstance(value, str) else []
    if isinstance(node, (cst.Tuple, cst.List, cst.Set)):
        out: list[str] = []
        for element in node.elements:
            if isinstance(element, cst.Element):
                out.extend(_strings(element.value))
        return out
    return []


class _ValueUses(cst.CSTVisitor):
    """Names of module functions used as values rather than called."""

    METADATA_DEPENDENCIES = (ParentNodeProvider,)

    def __init__(self, functions: set[str]) -> None:
        self.functions = functions
        self.uses: dict[str, int] = {}

    def visit_Name(self, node: cst.Name) -> None:
        if node.value not in self.functions:
            return
        parent = self.get_metadata(ParentNodeProvider, node, None)
        if isinstance(parent, cst.Call) and parent.func is node:
            return
        if isinstance(parent, (cst.FunctionDef, cst.ImportAlias, cst.Attribute)):
            return
        self.uses.setdefault(node.value, 0)


class Proposals(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (
        QualifiedNameProvider,
        PositionProvider,
        ParentNodeProvider,
        ScopeProvider,
    )

    def __init__(self, source: str, path: str, facts: _GuardFacts, value_uses: set[str]) -> None:
        self.source, self.path = source, path
        self.lines = source.splitlines(keepends=True)
        self.changes: list[Change] = []
        self.skipped: list[Skipped] = []
        self.facts = facts
        self.value_uses = value_uses
        self.role = classify_role(path)

    def _enclosing(self, node: cst.CSTNode) -> list[cst.CSTNode]:
        chain: list[cst.CSTNode] = []
        current = self.get_metadata(ParentNodeProvider, node, None)
        while current is not None:
            chain.append(current)
            current = self.get_metadata(ParentNodeProvider, current, None)
        return chain

    def _refusal(self, node: cst.CSTNode, algorithm: str) -> tuple[str, str] | None:
        if self.role != "source":
            return (
                "TEST_EXPECTATION",
                "Test and example code compares results against fixed expected values "
                f"computed with {algorithm}. Changing the hash here breaks those checks; "
                "update the expected values deliberately, together with the code under test.",
            )
        chain = self._enclosing(node)
        functions = [n for n in chain if isinstance(n, cst.FunctionDef)]
        scopes = [id(f) for f in functions] or [0]
        for key in scopes:
            if algorithm in self.facts.value_refs.get(key, set()):
                return (
                    "MIXED_USE",
                    f"The same scope also passes {algorithm} as a value (for example "
                    f"hash_func=hashlib.{algorithm.lower()}). Changing only this call would "
                    "leave the two out of step.",
                )
        for key in scopes:
            if algorithm in self.facts.compared.get(key, {}):
                return (
                    "PROTOCOL_NEGOTIATED",
                    f"This code compares a value with the name {algorithm}. A peer or a stored "
                    "format chooses the hash here, so replacing it would break compatibility.",
                )
        outermost = functions[-1] if functions else None
        if outermost is not None and outermost.name.value in self.value_uses:
            return (
                "STORED_FORMAT_DEFAULT",
                f"{outermost.name.value}() is used as a value (for example a default digest "
                "method). Its output is likely stored or verified later, so changing the hash "
                "would invalidate existing data.",
            )
        for ancestor in chain:
            if isinstance(ancestor, cst.Param):
                return (
                    "STORED_FORMAT_DEFAULT",
                    "The hash is a default argument value. Callers rely on it implicitly, so a "
                    "change alters every result produced with the default.",
                )
        return None

    def _offsets(self, node: cst.CSTNode) -> tuple[int, int, int]:
        position = self.get_metadata(PositionProvider, node)
        start = sum(map(len, self.lines[: position.start.line - 1])) + position.start.column
        end = sum(map(len, self.lines[: position.end.line - 1])) + position.end.column
        return start, end, position.start.line

    def add(
        self,
        node: cst.CSTNode,
        replacement: str,
        rule: str,
        module: str = "",
        name: str = "",
        extra: tuple[Edit, ...] = (),
    ) -> None:
        start, end, line = self._offsets(node)
        identity = hashlib.sha256(f"{self.path}:{start}:{rule}".encode()).hexdigest()[:24]
        text = self.lines[line - 1]
        column = start - sum(map(len, self.lines[: line - 1]))
        line_before = text.rstrip("\r\n")
        line_after = (text[:column] + replacement + text[column + (end - start) :]).rstrip("\r\n")
        self.changes.append(
            Change(
                id=identity,
                rule=rule,
                line=line,
                start=start,
                end=end,
                before=self.source[start:end],
                after=replacement,
                import_module=module,
                import_name=name,
                extra=extra,
                line_before=line_before,
                line_after=line_after,
            )
        )

    def _skip(self, node: cst.CSTNode, code: str, detail: str) -> None:
        position = self.get_metadata(PositionProvider, node)
        self.skipped.append(
            Skipped(
                path=self.path,
                line=position.start.line,
                rule="weak-hash-to-sha256",
                code=code,
                detail=detail,
            )
        )

    def visit_Call(self, node: cst.Call) -> None:
        if len(self.changes) >= 200:
            return
        names = self.get_metadata(QualifiedNameProvider, node.func, set())
        if len(names) != 1:
            return
        qualified = next(iter(names))
        if qualified.source.name != "IMPORT":
            return
        algorithm = _CANDIDATE_ALGORITHM.get(qualified.name)
        if qualified.name == "hashlib.new" and node.args:
            first = node.args[0]
            if not first.keyword and isinstance(first.value, cst.SimpleString):
                value = first.value.evaluated_value
                if isinstance(value, str):
                    algorithm = {"md5": "MD5", "sha1": "SHA1", "sha-1": "SHA1"}.get(value.lower())
        if algorithm is not None:
            refusal = self._refusal(node, algorithm)
            if refusal is not None:
                self._skip(node, *refusal)
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
                self._rename_call(node, node.func, module, name)
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

    def _rename_call(self, call: cst.Call, func: cst.Name, module: str, name: str) -> None:
        """``sha1(data)`` bound by ``from hashlib import sha1``: call the stronger function by
        its own name. Where the import binds only this call, rewrite that import in place;
        otherwise import the new name. Never invent a name; refuse on a clash."""
        clash = re.search(rf"\b{name}\b", self.source) and not re.search(
            rf"from\s+{re.escape(module)}\s+import\s+[^\n]*\b{name}\b", self.source
        )
        if clash:
            self._skip(
                call,
                "NAME_CONFLICT",
                f"The name {name} already means something else in this file, so the call "
                "cannot be renamed without shadowing it.",
            )
            return
        scope = self.get_metadata(ScopeProvider, func, None)
        alias_node: cst.ImportAlias | None = None
        accesses = 0
        if scope is not None:
            for assignment in scope[func.value]:
                node = getattr(assignment, "node", None)
                if isinstance(node, cst.ImportFrom) and not isinstance(node.names, cst.ImportStar):
                    for candidate in node.names:
                        if candidate.asname is None and candidate.evaluated_name == func.value:
                            alias_node = candidate
                            accesses = len(assignment.references)
        if alias_node is not None and accesses == 1:
            start, end, _ = self._offsets(alias_node.name)
            edit = Edit(start=start, end=end, before=self.source[start:end], after=name)
            self.add(func, name, "weak-hash-to-sha256", extra=(edit,))
        else:
            self.add(func, name, "weak-hash-to-sha256", module, name)


def propose_with_skips(source: str, path: str) -> tuple[FixFile | None, list[Skipped]]:
    if not safe_path(path):
        return None, []
    try:
        wrapper = MetadataWrapper(cst.parse_module(source))
        # Facts are keyed by node identity, so they must come from the wrapper's own copy.
        facts = _GuardFacts()
        wrapper.module.visit(facts)
        uses = _ValueUses(facts.module_functions)
        wrapper.visit(uses)
        visitor = Proposals(source, path, facts, set(uses.uses))
        wrapper.visit(visitor)
    except (cst.ParserSyntaxError, cst.CSTValidationError, RecursionError):
        return None, []
    if not visitor.changes:
        return None, visitor.skipped
    return (
        FixFile(
            path=path,
            source=source,
            sha256=hashlib.sha256(source.encode()).hexdigest(),
            changes=visitor.changes,
        ),
        visitor.skipped,
    )


def propose(source: str, path: str) -> FixFile | None:
    return propose_with_skips(source, path)[0]


def propose_repository(
    root: Path,
    files: list[Path],
    settings: ProductSettings,
    on_file: Callable[[FixFile], None] | None = None,
) -> FixPlan:
    results: list[FixFile] = []
    skipped: list[Skipped] = []
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
        if not _WEAK_HASH_TEXT.search(source):
            # Every proposal and refusal concerns MD5 or SHA-1, and each needs the name in
            # the text. Skipping the rest saves a full metadata parse per file.
            continue
        result, refused = propose_with_skips(source, path.relative_to(root).as_posix())
        skipped.extend(refused)
        if result:
            results.append(result)
            retained += len(source.encode())
            if on_file is not None:
                on_file(result)
    return FixPlan(files=results, limited=limited, skipped=skipped[:200])


def unified_diff(before: str, after: str, path: str, context: int = 3) -> str:
    """A unified diff that reads like ``git diff``. difflib's default "autojunk" treats very
    common lines (blank lines) as noise and folds unchanged ones into a hunk."""
    a, b = before.splitlines(keepends=True), after.splitlines(keepends=True)
    out = [f"--- a/{path}\n", f"+++ b/{path}\n"]
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    for group in matcher.get_grouped_opcodes(context):
        i1, i2, j1, j2 = group[0][1], group[-1][2], group[0][3], group[-1][4]
        out.append(f"@@ -{i1 + 1},{i2 - i1} +{j1 + 1},{j2 - j1} @@\n")
        for tag, a1, a2, b1, b2 in group:
            if tag == "equal":
                out += [" " + line for line in a[a1:a2]]
                continue
            out += ["-" + line for line in a[a1:a2]]
            out += ["+" + line for line in b[b1:b2]]
    return "".join(line if line.endswith("\n") else line + "\n" for line in out)


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
        edits = [Edit(start=c.start, end=c.end, before=c.before, after=c.after) for c in changes]
        edits += [edit for c in changes for edit in c.extra]
        for edit in sorted(edits, key=lambda e: e.start, reverse=True):
            if (
                edit.start < 0
                or edit.end > boundary
                or updated[edit.start : edit.end] != edit.before
            ):
                raise Reject("REVIEW_STALE", "Conflicting proposals. Scan again.")
            updated = updated[: edit.start] + edit.after + updated[edit.end :]
            boundary = edit.start
        try:
            context = CodemodContext()
            for change in changes:
                if change.import_module:
                    AddImportsVisitor.add_needed_import(
                        context,
                        change.import_module,
                        change.import_name,
                        asname=change.import_alias or None,
                    )
            updated = AddImportsVisitor(context).transform_module(cst.parse_module(updated)).code
            ast.parse(updated, filename=file.path)
        except (SyntaxError, cst.ParserSyntaxError, cst.CSTValidationError) as exc:
            raise Reject(
                "FIX_UNAVAILABLE", "The selected changes did not pass syntax validation."
            ) from exc
        diff = unified_diff(file.source, updated, file.path)
        output.append(
            {"path": file.path, "content": updated, "before_sha256": file.sha256, "diff": diff}
        )
    digest = hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest()
    return {
        "digest": digest,
        "files": output,
        "selected": sorted(chosen),
        "validation": (
            "Python syntax checked. Not verified: repository tests have not run on this change."
        ),
        "compatibility": HASH_NOTE,
    }
