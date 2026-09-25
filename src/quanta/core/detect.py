"""Crypto usage detection with LibCST and ruleset v2 (Master Plan 7.1 to 7.6).

Parsing is **pure text to tree**. The target module is never imported and never executed
(ADR-001); ``tests/security/test_no_target_import.py`` enforces it statically.

What is detected:

* ``crypto_call``: a call, or a reference (7.4), whose resolved qualified name is a
  ruleset ``site``. Each one records its role, category, algorithms and how the algorithm
  is selected (``configured``, ``literal``, ``forwarded`` or ``unspecified``, 7.6).
* ``algo_literal``: an algorithm named in a site's selector position, or a free selector
  such as ``hashes.SHA256()`` passed to ``key.sign`` (``free=True``).
* ``config_read``: an environment or configuration read in a selector position.

Coverage (7.5): every resolved call into a crypto library namespace is counted as matched
(a site, selector or benign rule) or unmatched, so the report can say how much of the
cryptography the ruleset recognised. A method called on the result of a matched call,
such as ``hashlib.sha256(x).hexdigest()``, chooses no algorithm and is not counted.

Declared limits: dynamic dispatch, ``getattr``, conditional imports, monkey-patching,
``**kwargs`` forwarding, metaprogramming and calls on key objects (``key.sign(...)``)
defeat static resolution. The test-time trace (``quanta.verify.trace``) measures that gap
per repository instead of hiding it.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import re
import signal
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import libcst as cst
from libcst.metadata import (
    Assignment,
    ExpressionContext,
    ExpressionContextProvider,
    MetadataWrapper,
    ParentNodeProvider,
    PositionProvider,
    QualifiedNameProvider,
    ScopeProvider,
)

from quanta.config import Settings, get_settings
from quanta.core.models import CryptoSite, Selection, UnparseableFile
from quanta.core.operations import find_operations, operation_category, quantum_flags
from quanta.core.roles import Role, classify_role
from quanta.core.ruleset_v2 import (
    ALGORITHMS,
    CRYPTO_MODULE_PREFIXES,
    RESULT_METHODS,
    RULES,
    SELECTOR_RULES,
    SITE_RULES,
    Rule,
    canonical,
)

#: Qualified names whose result is a configuration value rather than a literal (7.6).
_CONFIG_QUALIFIED_NAMES = frozenset(
    {"os.getenv", "os.environ.get", "os.environ.__getitem__", "configparser.ConfigParser.get"}
)

#: Leftmost identifiers that conventionally hold configuration. Only consulted inside a
#: selector position, so ``settings.SECRET_KEY`` passed as a key is not a selection (D7).
_CONFIG_NAME_HINTS = frozenset({"config", "settings", "cfg", "conf", "options", "opts", "env"})

#: Calls whose arguments name a type rather than configure cryptography.
_TYPE_CHECK_CALLS = frozenset(
    {"isinstance", "issubclass", "builtins.isinstance", "builtins.issubclass"}
)

_MAX_HOPS = 3

#: Parsing runs on a worker thread with a large stack. LibCST's native parser recurses on
#: nested expressions; on Windows the default 1 MB main-thread stack overflowed on a real
#: repository (round two, D17) and killed the whole process. A thread with its own stack
#: turns that into an ordinary, recoverable RecursionError.
_PARSE_STACK_BYTES = 128 * 1024 * 1024  # Windows rejects 256 MB (limit is exclusive)


@dataclass(frozen=True)
class FunctionRecord:
    """A function or method definition: a scope node in the CDG."""

    module: str
    name_path: str  # "digest" or "Class.method"
    file: str
    line: int
    col: int

    @property
    def qualname(self) -> str:
        return f"{self.module}.{self.name_path}"


@dataclass(frozen=True)
class ImportRecord:
    """A module-to-module dependency, for CDG ``import`` edges."""

    module: str
    target: str
    file: str
    line: int


@dataclass(frozen=True)
class CallRecord:
    """A resolved call, for one-hop ``call`` edges (always ``confidence: "low"``)."""

    caller_module: str
    caller_path: str | None  # None when the call is at module level
    callee: str
    file: str
    line: int
    col: int

    @property
    def caller_qualname(self) -> str:
        if not self.caller_path:
            return self.caller_module
        return f"{self.caller_module}.{self.caller_path}"


@dataclass
class DetectionResult:
    """Everything detection produces, including what it failed on."""

    sites: list[CryptoSite] = field(default_factory=list)
    unparseable: list[UnparseableFile] = field(default_factory=list)
    files_scanned: int = 0
    #: Test, docs, example and tooling files that name no crypto library anywhere in their
    #: text, so they cannot hold a finding; read, not parsed (round four).
    files_text_only: int = 0
    #: Files not read because the parse budget ran out (round four). Shipped code is read
    #: first, so a stop usually leaves only tests unread.
    files_unread: int = 0
    source_unread: int = 0
    functions: list[FunctionRecord] = field(default_factory=list)
    imports: list[ImportRecord] = field(default_factory=list)
    calls: list[CallRecord] = field(default_factory=list)
    modules: set[str] = field(default_factory=set)
    #: module name -> file role, for every parsed file.
    module_roles: dict[str, str] = field(default_factory=dict)
    #: module name -> POSIX path, for every parsed file.
    module_files: dict[str, str] = field(default_factory=dict)
    #: 7.5 counts, over ``source`` files only.
    api_matched: int = 0
    api_unmatched: int = 0
    unmatched_names: Counter[str] = field(default_factory=Counter)

    @property
    def crypto_calls(self) -> list[CryptoSite]:
        return [s for s in self.sites if s.kind == "crypto_call"]

    @property
    def algo_literals(self) -> list[CryptoSite]:
        return [s for s in self.sites if s.kind == "algo_literal"]

    @property
    def config_reads(self) -> list[CryptoSite]:
        return [s for s in self.sites if s.kind == "config_read"]

    @property
    def source_files(self) -> int:
        return sum(1 for r in self.module_roles.values() if r == "source")

    @property
    def coverage_ratio(self) -> float | None:
        total = self.api_matched + self.api_unmatched
        return None if total == 0 else self.api_matched / total


# ---------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------


def node_id(kind: str, file: str, line: int, col: int, name: str) -> str:
    """A stable, collision-resistant node identifier (NFR-03)."""
    digest = hashlib.sha256(f"{kind}|{file}|{line}|{col}|{name}".encode()).hexdigest()[:16]
    return f"{kind}-{digest}"


def module_name(file: Path, root: Path) -> str:
    """Derive a dotted module path from a file path."""
    rel = file.relative_to(root)
    parts = list(rel.parts)
    parts[-1] = rel.stem
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) if parts else rel.stem


class ParseTimeout(Exception):
    """A single file exceeded ``[analysis].parse_timeout_s`` (T3)."""


@contextmanager
def _parse_timeout(seconds: int) -> Iterator[None]:
    """Bound parse time for one file where ``SIGALRM`` is usable (POSIX main thread)."""
    usable = (
        seconds > 0
        and hasattr(signal, "SIGALRM")
        and threading.current_thread() is threading.main_thread()
    )
    if not usable:
        yield
        return

    def _raise(signum: int, frame: object) -> None:
        raise ParseTimeout(f"parse exceeded {seconds}s")

    previous = signal.signal(signal.SIGALRM, _raise)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _expr_name(node: cst.CSTNode) -> str:
    """Render a dotted expression back to source text, best effort."""
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        return f"{_expr_name(node.value)}.{node.attr.value}"
    if isinstance(node, cst.Call):
        return _expr_name(node.func)
    return type(node).__name__


def _root_name(node: cst.CSTNode) -> str:
    """The leftmost identifier of a dotted expression, a subscript or a call."""
    while True:
        if isinstance(node, (cst.Attribute, cst.Subscript)):
            node = node.value
        elif isinstance(node, cst.Call):
            node = node.func
        else:
            break
    return node.value.lower() if isinstance(node, cst.Name) else ""


def _string_values(node: cst.CSTNode) -> list[str] | None:
    """The string value(s) of a string literal, or of a list or tuple of them."""
    if isinstance(node, (cst.SimpleString, cst.ConcatenatedString)):
        evaluated = node.evaluated_value
        return [evaluated] if isinstance(evaluated, str) else None
    if isinstance(node, (cst.List, cst.Tuple)):
        out: list[str] = []
        for element in node.elements:
            if not isinstance(element, cst.Element):
                return None
            inner = _string_values(element.value)
            if inner is None:
                return None
            out.extend(inner)
        return out
    return None


# ---------------------------------------------------------------------------------------
# Visitor
# ---------------------------------------------------------------------------------------


class _CryptoVisitor(cst.CSTVisitor):
    """Collects crypto sites, the selectors that feed them, and coverage counts."""

    METADATA_DEPENDENCIES = (
        QualifiedNameProvider,
        PositionProvider,
        ScopeProvider,
        ParentNodeProvider,
        ExpressionContextProvider,
    )

    def __init__(self, file: str, module: str, role: Role) -> None:
        super().__init__()
        self.file = file
        self.module = module
        self.role = role
        self.sites: list[CryptoSite] = []
        self.functions: list[FunctionRecord] = []
        self.imports: list[ImportRecord] = []
        self.calls: list[CallRecord] = []
        self.matched = 0
        self.unmatched: Counter[str] = Counter()
        self._scope_stack: list[str] = []
        #: ids of nodes already accounted for: call funcs, selector positions and the
        #: subtrees of classified free selectors. Nothing inside them is re-classified.
        self._consumed: set[int] = set()
        self._selector_roots: set[int] = set()
        #: id of each call node that produced a crypto site, for the operations pass.
        self.producers: dict[int, CryptoSite] = {}

    # -- imports -------------------------------------------------------------------

    def visit_Import(self, node: cst.Import) -> bool:
        for alias in node.names:
            target = _expr_name(alias.name)
            if target:
                line, _ = self._position(node)
                self.imports.append(ImportRecord(self.module, target, self.file, line))
        return False  # names inside an import statement are never sites

    def visit_ImportFrom(self, node: cst.ImportFrom) -> bool:
        base = _expr_name(node.module) if node.module else ""
        line, _ = self._position(node)
        if isinstance(node.names, cst.ImportStar):
            if base:
                self.imports.append(ImportRecord(self.module, base, self.file, line))
            return False
        for alias in node.names:
            leaf = _expr_name(alias.name)
            target = f"{base}.{leaf}" if base else leaf
            if target:
                self.imports.append(ImportRecord(self.module, target, self.file, line))
        return False

    # -- scope tracking ------------------------------------------------------------

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        self._scope_stack.append(node.name.value)
        line, col = self._position(node)
        self.functions.append(
            FunctionRecord(self.module, ".".join(self._scope_stack), self.file, line, col)
        )
        return True

    def leave_FunctionDef(self, original_node: cst.FunctionDef) -> None:
        self._scope_stack.pop()

    def visit_ClassDef(self, node: cst.ClassDef) -> bool:
        self._scope_stack.append(node.name.value)
        return True

    def leave_ClassDef(self, original_node: cst.ClassDef) -> None:
        self._scope_stack.pop()

    def visit_Annotation(self, node: cst.Annotation) -> bool:
        # A type annotation names a type; it configures nothing (``ctx: ssl.SSLContext``).
        return False

    @property
    def _enclosing(self) -> str | None:
        return ".".join(self._scope_stack) if self._scope_stack else None

    # -- metadata helpers ------------------------------------------------------------

    def _position(self, node: cst.CSTNode) -> tuple[int, int]:
        try:
            pos = self.get_metadata(PositionProvider, node)
        except KeyError:
            return (0, 0)
        return (pos.start.line, pos.start.column)

    def _qualified_names(self, node: cst.CSTNode) -> set[str]:
        try:
            return {qn.name for qn in self.get_metadata(QualifiedNameProvider, node)}
        except Exception:
            # Providers raise on unusual constructs. An unresolved name is a missed
            # detection, which the benchmark measures as recall; never a crashed job.
            return set()

    def _rule_for(self, node: cst.CSTNode, table: dict[str, Rule]) -> Rule | None:
        matches = sorted(self._qualified_names(node) & table.keys())
        return table[matches[0]] if matches else None

    def _parent(self, node: cst.CSTNode) -> cst.CSTNode | None:
        try:
            return self.get_metadata(ParentNodeProvider, node)
        except KeyError:
            return None

    def _inside_selector_position(self, node: cst.CSTNode) -> bool:
        current: cst.CSTNode | None = node
        while current is not None:
            if id(current) in self._selector_roots:
                return True
            current = self._parent(current)
        return False

    def _inside_type_check(self, node: cst.CSTNode) -> bool:
        current = self._parent(node)
        while current is not None:
            if isinstance(current, cst.Call):
                names = self._qualified_names(current.func) | {_expr_name(current.func)}
                return bool(names & _TYPE_CHECK_CALLS)
            if isinstance(current, (cst.Arg, cst.Tuple, cst.Element)):
                current = self._parent(current)
                continue
            return False
        return False

    # -- selector analysis (7.6) -------------------------------------------------------

    def _selector_args(self, call: cst.Call, rule: Rule) -> tuple[list[cst.BaseExpression], bool]:
        """Expressions in explicit selector positions, and whether the call forwards."""
        positional: list[cst.BaseExpression] = []
        keywords: dict[str, cst.BaseExpression] = {}
        forwards = False
        for arg in call.args:
            if arg.star:
                forwards = True
                continue
            if arg.keyword is not None:
                keywords[arg.keyword.value] = arg.value
            elif not forwards:
                positional.append(arg.value)
        exprs: list[cst.BaseExpression] = []
        for position in rule.selector_args:
            if isinstance(position, int):
                if position < len(positional):
                    exprs.append(positional[position])
            elif position in keywords:
                exprs.append(keywords[position])
        return exprs, forwards

    def _binding_value(self, name: cst.Name) -> cst.BaseExpression | None:
        """The value of the single assignment that binds ``name`` in its scope, if any."""
        try:
            scope = self.get_metadata(ScopeProvider, name)
        except KeyError:
            return None
        if scope is None:
            return None
        assignments = [
            a
            for a in scope[name.value]
            if isinstance(a, Assignment) and isinstance(a.node, cst.Name)
        ]
        if len(assignments) != 1:
            return None
        target = assignments[0].node
        parent = self._parent(target)
        if isinstance(parent, cst.AssignTarget):
            assign = self._parent(parent)
            if isinstance(assign, cst.Assign) and len(assign.targets) == 1:
                return assign.value
        if isinstance(parent, cst.AnnAssign) and parent.value is not None:
            return parent.value
        return None

    def _algorithm_literal(
        self, expr: cst.CSTNode, rule: Rule, hops: int = 0
    ) -> list[tuple[str, str, cst.CSTNode]]:
        """Algorithm literals in ``expr``: ``(canonical_id, source_name, node)``."""
        strings = _string_values(expr)
        if strings is not None:
            found = []
            for value in strings:
                algo = canonical(value, token=rule.category == "token")
                if algo:
                    found.append((algo, value, expr))
            return found
        target = expr.func if isinstance(expr, cst.Call) else expr
        if isinstance(target, (cst.Name, cst.Attribute)):
            for table in (SELECTOR_RULES, SITE_RULES):
                matched = self._rule_for(target, table)
                if matched is not None and matched.algorithm:
                    return [(matched.algorithm, matched.qualified_name, expr)]
        if isinstance(expr, cst.Name) and hops < _MAX_HOPS:
            bound = self._binding_value(expr)
            if bound is not None:
                return self._algorithm_literal(bound, rule, hops + 1)
        return []

    def _config_derived(
        self, expr: cst.CSTNode, hops: int = 0, seen: set[int] | None = None
    ) -> str | None:
        """Name of the configuration read that selects ``expr``, if it is one (7.6)."""
        seen = seen if seen is not None else set()
        if id(expr) in seen or hops > _MAX_HOPS:
            return None
        seen.add(id(expr))
        if isinstance(expr, cst.Call):
            names = self._qualified_names(expr.func)
            if names & _CONFIG_QUALIFIED_NAMES:
                return _expr_name(expr.func)
            if names & {"getattr", "builtins.getattr"} and len(expr.args) >= 2:
                found = self._config_derived(expr.args[1].value, hops + 1, seen)
                if found:
                    return found
            func_config = self._config_derived(expr.func, hops + 1, seen)
            if func_config:
                return func_config
            if isinstance(expr.func, cst.Name):
                returned = self._module_function_returns_config(expr.func, hops, seen)
                if returned:
                    return returned
        if isinstance(expr, cst.Subscript):
            if self._qualified_names(expr.value) & {"os.environ"}:
                return "os.environ"
            for element in expr.slice:
                if isinstance(element.slice, cst.Index):
                    found = self._config_derived(element.slice.value, hops + 1, seen)
                    if found:
                        return found
        if (
            isinstance(expr, (cst.Name, cst.Attribute, cst.Subscript, cst.Call))
            and _root_name(expr) in _CONFIG_NAME_HINTS
        ):
            return _expr_name(expr)
        if isinstance(expr, cst.Name):
            value = self._binding_value(expr)
            if value is not None:
                return self._config_derived(value, hops + 1, seen)
        return None

    def _module_function_returns_config(
        self, name: cst.Name, hops: int, seen: set[int]
    ) -> str | None:
        """Rule 4: a module-level function whose every ``return`` is configuration-derived."""
        try:
            scope = self.get_metadata(ScopeProvider, name)
        except KeyError:
            return None
        if scope is None:
            return None
        defs = [
            a.node
            for a in scope[name.value]
            if isinstance(a, Assignment) and isinstance(a.node, cst.FunctionDef)
        ]
        if len(defs) != 1:
            return None
        returns: list[cst.Return] = []

        class _Returns(cst.CSTVisitor):
            def visit_Return(self, node: cst.Return) -> None:
                returns.append(node)

            def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
                return node is defs[0]

        defs[0].visit(_Returns())
        if not returns or any(r.value is None for r in returns):
            return None
        found = [self._config_derived(r.value, hops + 1, seen) for r in returns if r.value]
        return found[0] if found and all(found) else None

    # -- detection -----------------------------------------------------------------

    def visit_Call(self, node: cst.Call) -> bool:
        resolved = self._qualified_names(node.func)
        line, col = self._position(node)

        for callee in sorted(resolved):
            self.calls.append(
                CallRecord(self.module, self._enclosing, callee, self.file, line, col)
            )

        self._count_coverage(resolved)
        self._consumed.add(id(node.func))

        rule = self._rule_for(node.func, SITE_RULES)
        if rule is not None:
            self._emit_site(node, rule, "call")
            return True

        selector = self._rule_for(node.func, SELECTOR_RULES)
        if selector is not None and not self._inside_selector_position(node):
            self._emit_free_selector(node, selector)
            return False  # nested selectors are part of this literal (7.6)
        return True

    def _count_coverage(self, resolved: set[str]) -> None:
        if self.role != "source":
            return
        crypto = sorted(n for n in resolved if n.startswith(CRYPTO_MODULE_PREFIXES))
        if not crypto:
            return
        name = crypto[0]
        if name in RULES:
            self.matched += 1
            return
        head, _, last = name.rpartition(".")
        if last in RESULT_METHODS and head in RULES:
            return  # hmac.new(...).digest(): no algorithm choice (7.5 correction)
        self.unmatched[name] += 1

    def _reference_candidate(self, node: cst.Name | cst.Attribute) -> None:
        if id(node) in self._consumed:
            return
        try:
            context = self.get_metadata(ExpressionContextProvider, node)
        except KeyError:
            context = None
        if context is not ExpressionContext.LOAD:
            return
        parent = self._parent(node)
        if isinstance(parent, cst.Call) and parent.func is node:
            return
        if isinstance(parent, cst.Attribute) and parent.value is node:
            return  # part of a longer dotted name; the outer node decides
        rule = self._rule_for(node, SITE_RULES)
        if rule is not None:
            if self._inside_selector_position(node) or self._inside_type_check(node):
                return
            self._emit_site(node, rule, "reference")
            return
        selector = self._rule_for(node, SELECTOR_RULES)
        if (
            selector is not None
            and not self._inside_selector_position(node)
            and not self._inside_type_check(node)
        ):
            self._emit_free_selector(node, selector)

    def visit_Name(self, node: cst.Name) -> bool:
        self._reference_candidate(node)
        return True

    def visit_Attribute(self, node: cst.Attribute) -> bool:
        self._reference_candidate(node)
        return True

    # -- emitters -------------------------------------------------------------------

    def _emit_site(self, node: cst.CSTNode, rule: Rule, form: str) -> None:
        line, col = self._position(node)
        site_id = node_id("crypto_call", self.file, line, col, rule.qualified_name)
        literals: list[tuple[str, str, cst.CSTNode]] = []
        configs: list[tuple[str, cst.CSTNode]] = []
        selection: Selection
        if form == "call" and isinstance(node, cst.Call):
            exprs, forwards = self._selector_args(node, rule)
            for expr in exprs:
                self._selector_roots.add(id(expr))
            for expr in exprs:
                name = self._config_derived(expr)
                if name:
                    configs.append((name, expr))
                else:
                    literals.extend(self._algorithm_literal(expr, rule))
            if rule.selector_args:
                if not exprs and forwards:
                    selection = "forwarded"
                elif configs:
                    selection = "configured"
                elif literals:
                    selection = "literal"
                elif exprs:
                    selection = "forwarded"
                elif rule.default_algorithm or rule.algorithm:
                    selection = "literal"
                else:
                    selection = "unspecified"
            else:
                selection = "literal" if rule.algorithm else "unspecified"
        else:
            selection = "literal" if rule.algorithm else "unspecified"

        chosen = [algo for algo, _, _ in literals]
        if not chosen and not configs and rule.default_algorithm and form == "call":
            chosen = [rule.default_algorithm]
        algorithm = rule.algorithm or (chosen[0] if chosen else None)
        algorithms = tuple(dict.fromkeys(([rule.algorithm] if rule.algorithm else []) + chosen))
        infos = [ALGORITHMS[a] for a in algorithms if a in ALGORITHMS]
        site = CryptoSite(
            site_id=site_id,
            file=self.file,
            line=line,
            col=col,
            qualified_name=rule.qualified_name,
            kind="crypto_call",
            algorithm=algorithm,
            algorithms=algorithms,
            module=self.module,
            weak=any(i.weak for i in infos),
            quantum_vulnerable=any(i.quantum_vulnerable for i in infos),
            enclosing_function=self._enclosing,
            role=self.role,
            form="call" if form == "call" else "reference",
            category=rule.category,
            selection=selection,
            scored=rule.scored,
        )
        self.sites.append(site)
        if form == "call":
            self.producers[id(node)] = site
        for algo, literal_name, literal_node in literals:
            self._emit_selector_node("algo_literal", literal_name, literal_node, site_id, algo)
        for config_name, config_node in configs:
            self._emit_selector_node("config_read", config_name, config_node, site_id, None)

    def _emit_selector_node(
        self,
        kind: str,
        name: str,
        node: cst.CSTNode,
        parent_site: str | None,
        algorithm: str | None,
        *,
        free: bool = False,
    ) -> None:
        line, col = self._position(node)
        info = ALGORITHMS.get(algorithm) if algorithm else None
        self.sites.append(
            CryptoSite(
                site_id=node_id(kind, self.file, line, col, name),
                file=self.file,
                line=line,
                col=col,
                qualified_name=name,
                kind="algo_literal" if kind == "algo_literal" else "config_read",
                algorithm=algorithm,
                algorithms=(algorithm,) if algorithm else (),
                module=self.module,
                weak=bool(info and info.weak),
                quantum_vulnerable=bool(info and info.quantum_vulnerable),
                enclosing_function=self._enclosing,
                parent_site_id=parent_site,
                role=self.role,
                free=free,
                selection="literal" if free else None,
            )
        )

    def _emit_free_selector(self, node: cst.CSTNode, rule: Rule) -> None:
        self._emit_selector_node(
            "algo_literal", rule.qualified_name, node, None, rule.algorithm, free=True
        )
        self._mark_subtree(node)

    def _mark_subtree(self, node: cst.CSTNode) -> None:
        stack = [node]
        while stack:
            current = stack.pop()
            self._consumed.add(id(current))
            stack.extend(current.children)


# ---------------------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------------------


def _parse_and_visit(source: str, visitor: _CryptoVisitor) -> None:
    module = cst.parse_module(source)
    wrapper = MetadataWrapper(module, unsafe_skip_copy=True)
    wrapper.visit(visitor)
    _add_operations(wrapper, visitor)


def _add_operations(wrapper: MetadataWrapper, visitor: _CryptoVisitor) -> None:
    """Round four: operations on crypto objects (``key.sign``, ``ctx.wrap_socket``)."""
    seen = {(s.line, s.col) for s in visitor.sites if s.kind == "crypto_call"}
    for op in find_operations(wrapper, visitor.producers):
        if (op.line, op.col) in seen:
            continue
        seen.add((op.line, op.col))
        name = f"{op.taint.qualified_name}.{op.operation}"
        weak, quantum = quantum_flags(op.taint.algorithms)
        visitor.sites.append(
            CryptoSite(
                site_id=node_id("crypto_call", visitor.file, op.line, op.col, name),
                file=visitor.file,
                line=op.line,
                col=op.col,
                qualified_name=name,
                kind="crypto_call",
                algorithm=op.taint.algorithms[0] if op.taint.algorithms else None,
                algorithms=op.taint.algorithms,
                module=visitor.module,
                weak=weak,
                quantum_vulnerable=quantum,
                enclosing_function=op.scope,
                role=visitor.role,
                form="operation",
                category=operation_category(op.operation, op.taint),
                selection="literal" if op.taint.algorithms else "unspecified",
                scored=False,
            )
        )


def _run_with_large_stack(source: str, visitor: _CryptoVisitor) -> BaseException | None:
    """Parse on a thread with its own large stack; return the exception, if any."""
    outcome: list[BaseException | None] = [None]

    def work() -> None:
        try:
            _parse_and_visit(source, visitor)
        except BaseException as exc:  # handed back to the caller, never swallowed
            outcome[0] = exc

    previous = threading.stack_size()
    try:
        threading.stack_size(_PARSE_STACK_BYTES)
        thread = threading.Thread(target=work, name="quanta-parse", daemon=True)
    finally:
        threading.stack_size(previous)
    thread.start()
    thread.join()
    return outcome[0]


#: Files at least this large are parsed in a disposable child process. A generated
#: 675 KB data module (CPython's ``pydoc_data/topics.py``, vendored in a sampled
#: repository) overflows the native stack of LibCST's parser even on a 128 MB thread, and a
#: native stack overflow cannot be caught: it kills the process. In a child it only kills
#: the child, and the file is recorded as unparseable (round three, D17).
#:
#: The child is this interpreter running :func:`_isolated_entry`, started with
#: ``multiprocessing`` exactly as ``web/worker.py`` starts the analyzer. No external
#: program runs and no target code is imported: the child only parses text, like the
#: parent. The channel is a one-way ``os.pipe`` because the sandbox's seccomp filter
#: blocks ``socketpair`` (``web/sandbox.py``).
ISOLATE_BYTES = 200_000
_ISOLATE_TIMEOUT_S = 120


def _isolated_entry(path: str, root: str, connection: Any) -> None:
    """Child side: detect one file and send the result as JSON text.

    The parent bounds the child at ``_ISOLATE_TIMEOUT_S``, so the child does not also apply
    the 5-second per-file budget (which is sized for ordinary files and would cut every
    large file off on POSIX, where it is enforced).
    """
    settings = get_settings().model_copy(deep=True)
    settings.analysis.parse_timeout_s = 0
    result = detect_file(Path(path), Path(root), settings, isolate=False)
    connection.send(json.dumps(result_to_json(result)))
    connection.close()


def result_to_json(result: DetectionResult) -> dict[str, object]:
    return {
        "sites": [s.model_dump(mode="json") for s in result.sites],
        "unparseable": [u.model_dump(mode="json") for u in result.unparseable],
        "files_scanned": result.files_scanned,
        "files_text_only": result.files_text_only,
        "files_unread": result.files_unread,
        "source_unread": result.source_unread,
        "functions": [vars(f) for f in result.functions],
        "imports": [vars(i) for i in result.imports],
        "calls": [vars(c) for c in result.calls],
        "modules": sorted(result.modules),
        "module_roles": result.module_roles,
        "module_files": result.module_files,
        "api_matched": result.api_matched,
        "api_unmatched": result.api_unmatched,
        "unmatched_names": dict(result.unmatched_names),
    }


def result_from_json(data: dict[str, Any]) -> DetectionResult:
    return DetectionResult(
        sites=[CryptoSite.model_validate(s) for s in data["sites"]],
        unparseable=[UnparseableFile.model_validate(u) for u in data["unparseable"]],
        files_scanned=int(data["files_scanned"]),
        files_text_only=int(data.get("files_text_only", 0)),
        files_unread=int(data.get("files_unread", 0)),
        source_unread=int(data.get("source_unread", 0)),
        functions=[FunctionRecord(**f) for f in data["functions"]],
        imports=[ImportRecord(**i) for i in data["imports"]],
        calls=[CallRecord(**c) for c in data["calls"]],
        modules=set(data["modules"]),
        module_roles=dict(data["module_roles"]),
        module_files=dict(data["module_files"]),
        api_matched=int(data["api_matched"]),
        api_unmatched=int(data["api_unmatched"]),
        unmatched_names=Counter(data["unmatched_names"]),
    )


def _detect_isolated(path: Path, root: Path, rel: str) -> DetectionResult:
    """Run :func:`detect_file` for one large file in a disposable child process."""

    def unparseable(reason: str) -> DetectionResult:
        return DetectionResult(unparseable=[UnparseableFile(file=rel, reason=reason)])

    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_ISOLATED_TARGET, args=(str(path), str(root), sender), daemon=True
    )
    try:
        process.start()
    except OSError:
        return unparseable("parser process could not start")
    sender.close()
    payload: str | None = None
    try:
        if receiver.poll(_ISOLATE_TIMEOUT_S):
            payload = receiver.recv()
    except (EOFError, OSError):
        payload = None
    finally:
        receiver.close()
    process.join(timeout=5)
    if process.is_alive():
        process.kill()
        process.join(timeout=5)
        return unparseable("parse exceeded the isolation limit")
    if payload is None:
        return unparseable(f"parser process failed (exit {process.exitcode}); isolated")
    try:
        return result_from_json(json.loads(payload))
    except (ValueError, KeyError, TypeError):
        return unparseable("parser process returned no result")


#: Indirection so tests can simulate a native crash in the child.
_ISOLATED_TARGET = _isolated_entry


def detect_file(
    path: Path, root: Path, settings: Settings | None = None, *, isolate: bool = True
) -> DetectionResult:
    """Detect crypto usage in one file. Never raises for target-code problems."""
    cfg = settings or get_settings()
    result = DetectionResult()
    root = root.resolve()
    path = path.resolve()
    # POSIX paths in every artifact, on every operating system (7.1, fixes D8).
    rel = path.relative_to(root).as_posix()
    role = classify_role(rel)

    try:
        size = path.stat().st_size
        if isolate and size >= ISOLATE_BYTES:
            return _detect_isolated(path, root, rel)
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.unparseable.append(
            UnparseableFile(file=rel, reason=f"unreadable: {type(exc).__name__}")
        )
        return result

    module = module_name(path, root)
    if role != "source" and not _CRYPTO_TEXT.search(source):
        # Every rule matches a qualified name rooted in one of these libraries, and a name
        # can only resolve through an import that spells it. Shipped code is always parsed:
        # the graph and the score need all of it.
        result.modules.add(module)
        result.module_roles[module] = role
        result.module_files[module] = rel
        result.files_scanned = 1
        result.files_text_only = 1
        return result
    visitor = _CryptoVisitor(file=rel, module=module, role=role)
    error: BaseException | None
    try:
        with _parse_timeout(cfg.analysis.parse_timeout_s):
            error = _run_with_large_stack(source, visitor)
    except ParseTimeout as exc:
        # The parse thread is a daemon; the per-job watchdog bounds what it can still use.
        error = exc
    if error is not None:
        if isinstance(error, cst.ParserSyntaxError):
            reason = f"syntax error: {error.message}"
        elif isinstance(error, RecursionError):
            reason = "expression nested too deeply"
        elif isinstance(error, ParseTimeout):
            reason = str(error)
        elif isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise error
        else:
            # A parser bug on hostile input must degrade one file, never the whole job.
            reason = type(error).__name__
        result.unparseable.append(UnparseableFile(file=rel, reason=reason))
        return result

    result.sites.extend(visitor.sites)
    result.functions.extend(visitor.functions)
    result.imports.extend(visitor.imports)
    result.calls.extend(visitor.calls)
    result.modules.add(module)
    result.module_roles[module] = role
    result.module_files[module] = rel
    result.api_matched = visitor.matched
    result.api_unmatched = sum(visitor.unmatched.values())
    result.unmatched_names = visitor.unmatched
    result.files_scanned = 1
    return result


# ---------------------------------------------------------------------------------------
# Round five: a repository that IS the cryptography
# ---------------------------------------------------------------------------------------

#: Methods that perform the scheme once a key class is known to be the library's own.
_IMPL_METHODS = {
    "sign": "signature",
    "sign_digest": "signature",
    "sign_deterministic": "signature",
    "sign_digest_deterministic": "signature",
    "sign_number": "signature",
    "verify": "signature",
    "verify_digest": "signature",
    "encrypt": "key_agreement",
    "decrypt": "key_agreement",
    "exchange": "key_agreement",
    "generate": "key_generation",
}

#: Generic tier: a public-key operation built from modular exponentiation.
_MODEXP_FAMILIES = (
    ("rsa", "RSA"),
    ("dsa", "DSA"),
    ("elgamal", "DH"),
    ("diffie", "DH"),
    ("dh", "DH"),
)
_MODEXP_OPERATIONS = re.compile(
    r"^(sign|verify|encrypt|decrypt|exchange|keygen|generate_keys?|newkeys|shared_secret)$"
)


def _import_path(module: str) -> list[str]:
    """``src.ecdsa.keys`` is imported as ``ecdsa.keys``: drop a source-layout prefix."""
    parts = module.split(".")
    if len(parts) > 1 and parts[0] in {"src", "lib", "python"}:
        parts = parts[1:]
    return parts


def _library_tails() -> dict[str, dict[str, tuple[str, str]]]:
    """For every library whose rules name a quantum-vulnerable algorithm: rule name without
    the library prefix (``SigningKey.generate``) -> (algorithm, category)."""
    tails: dict[str, dict[str, tuple[str, str]]] = {}
    for name, rule in SITE_RULES.items():
        algorithm = rule.algorithm
        if not algorithm or algorithm not in ALGORITHMS:
            continue
        if not ALGORITHMS[algorithm].quantum_vulnerable:
            continue
        library, _, tail = name.partition(".")
        if tail:
            tails.setdefault(library, {})[tail] = (algorithm, rule.category)
    return tails


def _add_implementations(result: DetectionResult) -> None:
    """Report the definitions through which a repository provides a quantum-vulnerable
    scheme itself: python-ecdsa's ``SigningKey.sign``, python-rsa's ``newkeys``.

    Tier 1 is library identity: the repository's own package is a library the rules
    know (``ecdsa``, ``rsa``), and it defines the functions those rules name, or the
    signing and key exchange methods of the key classes they name. Tier 2 is generic:
    a function named for a public-key operation, in a module or class named for RSA, DSA
    or Diffie-Hellman, that computes with ``pow()``. Shipped code only; inventory only.
    """
    tails = _library_tails()
    pow_callers = {c.caller_qualname for c in result.calls if c.callee == "builtins.pow"}
    # A signature line can already hold a site (``hashfunc=sha1`` as a default); keep both.
    seen = {s.site_id for s in result.sites}
    found: list[CryptoSite] = []
    for record in result.functions:
        if result.module_roles.get(record.module) != "source":
            continue
        parts = _import_path(record.module)
        library = parts[0]
        method = record.name_path.rsplit(".", 1)[-1]
        match: tuple[str, str] | None = None
        if library in tails:
            known = tails[library]
            match = known.get(record.name_path)
            if match is None and "." in record.name_path and method in _IMPL_METHODS:
                owner = record.name_path.rsplit(".", 1)[0]
                owned = [v for k, v in known.items() if k.split(".")[0] == owner]
                if owned:
                    match = (owned[0][0], _IMPL_METHODS[method])
        if match is None and _MODEXP_OPERATIONS.match(method):
            where = ".".join([*parts, *record.name_path.split(".")[:-1]]).lower()
            words = set(re.split(r"[^a-z0-9]+", where))
            family = next((alg for token, alg in _MODEXP_FAMILIES if token in words), None)
            qualname = f"{record.module}.{record.name_path}"
            if family and qualname in pow_callers:
                match = (family, _IMPL_METHODS.get(method, "signature"))
        if match is None:
            continue
        algorithm, category = match
        weak, quantum = quantum_flags((algorithm,))
        name = ".".join([*parts, record.name_path])
        site_id = node_id("crypto_call", record.file, record.line, record.col, name)
        if site_id in seen:
            continue
        seen.add(site_id)
        found.append(
            CryptoSite(
                site_id=site_id,
                file=record.file,
                line=record.line,
                col=record.col,
                qualified_name=name,
                kind="crypto_call",
                algorithm=algorithm,
                algorithms=(algorithm,),
                module=record.module,
                weak=weak,
                quantum_vulnerable=quantum,
                enclosing_function=f"{record.module}.{record.name_path}",
                role="source",
                form="implementation",
                category=category,
                selection="literal",
                scored=False,
            )
        )
    result.sites.extend(found)


#: The top-level module of every rule and coverage prefix, as a whole word. A non-shipped
#: file whose text contains none of them cannot produce a site.
_CRYPTO_TEXT = re.compile(
    r"\b(?:"
    + "|".join(
        sorted(
            {name.split(".")[0] for name in RULES}
            | {p.split(".")[0] for p in CRYPTO_MODULE_PREFIXES}
        )
    )
    + r")\b"
)

#: Below this many files a process pool costs more to start than it saves.
PARALLEL_MIN_FILES = 48


def _detect_one_json(path: str, root: str, settings: Settings) -> dict[str, object]:
    """Pool side of :func:`detect_repository`: one file, returned as plain data."""
    return result_to_json(detect_file(Path(path), Path(root), settings))


def _detect_all(files: list[Path], root: Path, cfg: Settings) -> Iterable[DetectionResult]:
    """Per-file results in file order, parsed by a process pool when the repository is
    large enough. If the pool cannot start or breaks (a restricted sandbox, a native crash),
    the remaining files are parsed here, one by one, so the answer never depends on it."""
    workers = min(cfg.analysis.parse_workers, os.cpu_count() or 1)
    done = 0
    if workers > 1 and len(files) >= PARALLEL_MIN_FILES:
        pool: ProcessPoolExecutor | None = None
        try:
            context = multiprocessing.get_context("spawn")
            pool = ProcessPoolExecutor(max_workers=workers, mp_context=context)
            results = pool.map(
                _detect_one_json,
                [str(p) for p in files],
                [str(root)] * len(files),
                [cfg] * len(files),
                chunksize=4,
            )
            for data in results:
                yield result_from_json(data)
                done += 1
        except (BrokenProcessPool, OSError, PermissionError, RuntimeError):
            pass
        finally:
            # On a stop (the time budget) queued work is cancelled, not waited for.
            if pool is not None:
                pool.shutdown(wait=False, cancel_futures=True)
    for path in files[done:]:
        yield detect_file(path, root, cfg)


def detect_repository(
    files: list[Path],
    root: Path,
    settings: Settings | None = None,
    on_file: Callable[[int, int, DetectionResult], None] | None = None,
    deadline: float | None = None,
) -> DetectionResult:
    """Detect across a file list, aggregating sites and unparseable records (PROC-02).

    With a ``deadline`` (``time.monotonic()`` value), shipped code is read first and reading
    stops when the deadline passes; the files not reached are counted, never hidden.

    Unparseable files are excluded from the denominator but **not** from the report: a
    silently dropped file is an unmeasured false negative.

    ``on_file(index, total, result)`` is called after each file, so a viewer can watch
    findings arrive while the rest of the repository is still being parsed.
    """
    cfg = settings or get_settings()
    combined = DetectionResult()
    if deadline is not None:
        root_resolved = root.resolve()

        def shipped_first(path: Path) -> bool:
            try:
                return (
                    classify_role(path.resolve().relative_to(root_resolved).as_posix()) != "source"
                )
            except ValueError:
                return True

        files = sorted(files, key=shipped_first)  # stable: file order kept within each group

    read = 0
    stream = _detect_all(files, root, cfg)
    for index, one in enumerate(stream, 1):
        read = index
        if on_file is not None:
            on_file(index, len(files), one)
        combined.sites.extend(one.sites)
        combined.unparseable.extend(one.unparseable)
        combined.files_scanned += one.files_scanned
        combined.files_text_only += one.files_text_only
        combined.functions.extend(one.functions)
        combined.imports.extend(one.imports)
        combined.calls.extend(one.calls)
        combined.modules |= one.modules
        combined.module_roles.update(one.module_roles)
        combined.module_files.update(one.module_files)
        combined.api_matched += one.api_matched
        combined.api_unmatched += one.api_unmatched
        combined.unmatched_names.update(one.unmatched_names)
        if deadline is not None and time.monotonic() > deadline and index < len(files):
            break
    if read < len(files):
        close = getattr(stream, "close", None)
        if close is not None:
            close()
        rest = files[read:]
        combined.files_unread = len(rest)
        root_resolved = root.resolve()
        combined.source_unread = sum(
            1
            for p in rest
            if classify_role(p.resolve().relative_to(root_resolved).as_posix()) == "source"
        )

    _add_implementations(combined)
    # Sorted output everywhere: NFR-03 requires byte-identical artifacts across runs.
    combined.sites.sort(key=lambda s: (s.file, s.line, s.col, s.kind, s.qualified_name))
    combined.unparseable.sort(key=lambda u: u.file)
    combined.functions.sort(key=lambda f: (f.file, f.line, f.col, f.name_path))
    combined.imports.sort(key=lambda i: (i.file, i.line, i.target))
    combined.calls.sort(key=lambda c: (c.file, c.line, c.col, c.callee))
    return combined
