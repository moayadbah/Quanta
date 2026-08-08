"""Crypto usage detection with LibCST (PROC-02, PROC-03).

Parsing is **pure text to tree**. The target module is never imported and never executed
— that is ADR-001, and ``tests/security/test_no_target_import.py`` enforces it statically.

What is detected, per §5.3.2:

* ``crypto_call``   — a ``Call`` whose resolved qualified name is in the versioned ruleset
* ``algo_literal``  — an algorithm named by enum or string *at* a crypto site
* ``config_read``   — an environment or configuration read that feeds a crypto site

The last two are what distinguish "the algorithm is hard-coded" from "the algorithm is
configuration-driven", which is the policy/mechanism separation NIST CSWP 39 names as a
determinant of agility, and which the ``f_config`` factor scores.

Declared limits, printed as threats to validity rather than buried (§3.8): dynamic
dispatch, ``getattr``/``setattr``, conditional imports, monkey-patching, ``**kwargs``
forwarding and metaprogramming all defeat this analysis. The hand-labelled benchmark
exists to *quantify* the resulting false-negative rate, not to hide it.
"""

from __future__ import annotations

import hashlib
import signal
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import libcst as cst
from libcst.metadata import (
    MetadataWrapper,
    PositionProvider,
    QualifiedNameProvider,
    ScopeProvider,
)

from quanta.config import Settings, get_settings
from quanta.core.models import CryptoSite, UnparseableFile
from quanta.core.rules import (
    ALGORITHM_LITERALS,
    CRYPTO_QUALIFIED_NAMES,
    classify_algorithm,
)

#: Qualified names whose result is a configuration value rather than a literal.
_CONFIG_QUALIFIED_NAMES = frozenset(
    {"os.getenv", "os.environ.get", "os.environ.__getitem__", "configparser.ConfigParser.get"}
)

#: Identifiers that conventionally hold a configuration object. Heuristic by nature, which
#: is why f_config is a *ratio* rather than a claim about any individual site.
_CONFIG_NAME_HINTS = frozenset({"config", "settings", "cfg", "conf", "options", "opts", "env"})

#: Case- and separator-insensitive lookup for algorithm names as they are actually spelled.
_ALGO_LOOKUP = {a.upper().replace("-", "").replace("_", ""): a for a in ALGORITHM_LITERALS}

#: Longest first, then alphabetical, so prefix matching is greedy *and* deterministic.
_ALGO_KEYS_BY_LENGTH = sorted(_ALGO_LOOKUP, key=lambda k: (-len(k), k))


@dataclass
class DetectionResult:
    """Everything detection produces, including what it failed on."""

    sites: list[CryptoSite] = field(default_factory=list)
    unparseable: list[UnparseableFile] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def crypto_calls(self) -> list[CryptoSite]:
        return [s for s in self.sites if s.kind == "crypto_call"]

    @property
    def algo_literals(self) -> list[CryptoSite]:
        return [s for s in self.sites if s.kind == "algo_literal"]

    @property
    def config_reads(self) -> list[CryptoSite]:
        return [s for s in self.sites if s.kind == "config_read"]


# ---------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------


def node_id(kind: str, file: str, line: int, col: int, name: str) -> str:
    """A stable, collision-resistant node identifier.

    Derived only from position and name, never from iteration order or a counter, so the
    same repository at the same commit yields the same ids on every run (NFR-03).
    """
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
    """Bound parse time for one file.

    A pathological file is a cheap denial-of-service against a parser, so the budget is
    real. ``SIGALRM`` only works on the main thread of a POSIX process; elsewhere this is
    a no-op and the outer per-job watchdog remains the backstop.
    """
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


def _normalise(text: str) -> str:
    return text.upper().replace("-", "").replace("_", "")


def _algorithm_from_name(name: str) -> str | None:
    """Map a qualified name onto a known algorithm.

    Every dotted segment is considered, not just the trailing one: the algorithm is
    frequently in the module rather than the callable, as in
    ``...asymmetric.x25519.X25519PrivateKey.generate`` — whose tail is ``generate``.
    Getting this wrong silently under-reports ``quantum_vulnerable``, which is the
    column the whole report exists to populate.

    Exact segment matches win. Failing that, a segment may *begin* with an algorithm
    name, which is how ``AESGCM`` resolves to ``AES`` and ``X25519PrivateKey`` to
    ``X25519``. Candidates are sorted longest-first so ``ChaCha20Poly1305`` prefers
    ``ChaCha20`` over any shorter prefix, and the result is deterministic.
    """
    segments = [_normalise(s) for s in name.split(".")]

    for segment in segments:
        if segment in _ALGO_LOOKUP:
            return _ALGO_LOOKUP[segment]

    for segment in segments:
        for key in _ALGO_KEYS_BY_LENGTH:
            if len(key) >= 3 and segment.startswith(key):
                return _ALGO_LOOKUP[key]
    return None


# ---------------------------------------------------------------------------------------
# Visitor
# ---------------------------------------------------------------------------------------


class _CryptoVisitor(cst.CSTVisitor):
    """Collects crypto call sites and the selectors that feed them."""

    METADATA_DEPENDENCIES = (QualifiedNameProvider, PositionProvider, ScopeProvider)

    def __init__(self, file: str, module: str) -> None:
        super().__init__()
        self.file = file
        self.module = module
        self.sites: list[CryptoSite] = []
        self._scope_stack: list[str] = []

    # -- scope tracking ------------------------------------------------------------

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        self._scope_stack.append(node.name.value)
        return True

    def leave_FunctionDef(self, original_node: cst.FunctionDef) -> None:
        self._scope_stack.pop()

    def visit_ClassDef(self, node: cst.ClassDef) -> bool:
        self._scope_stack.append(node.name.value)
        return True

    def leave_ClassDef(self, original_node: cst.ClassDef) -> None:
        self._scope_stack.pop()

    @property
    def _enclosing(self) -> str | None:
        return ".".join(self._scope_stack) if self._scope_stack else None

    # -- position ------------------------------------------------------------------

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
            # Providers raise a variety of errors on unusual constructs (unresolvable
            # scopes, exotic decorators). An unresolved name is a missed detection, which
            # the benchmark measures as recall — never a crashed job.
            return set()

    # -- detection -----------------------------------------------------------------

    def visit_Call(self, node: cst.Call) -> bool:
        matches = self._qualified_names(node.func) & CRYPTO_QUALIFIED_NAMES
        if not matches:
            return True

        qualified_name = sorted(matches)[0]  # deterministic when a name resolves twice
        line, col = self._position(node)
        site_id = node_id("crypto_call", self.file, line, col, qualified_name)

        algorithm = _algorithm_from_name(qualified_name)
        weak, quantum = classify_algorithm(algorithm) if algorithm else (False, False)

        self.sites.append(
            CryptoSite(
                site_id=site_id,
                file=self.file,
                line=line,
                col=col,
                qualified_name=qualified_name,
                kind="crypto_call",
                algorithm=algorithm,
                module=self.module,
                weak=weak,
                quantum_vulnerable=quantum,
                enclosing_function=self._enclosing,
            )
        )

        self._collect_selectors(node, site_id)
        return True

    def _collect_selectors(self, call: cst.Call, site_id: str) -> None:
        """Find the algorithm literals and config reads that select this call's algorithm."""
        for arg in call.args:
            for found in self._walk_selectors(arg.value):
                kind, name, node = found
                line, col = self._position(node)
                algorithm = _algorithm_from_name(name) if kind == "algo_literal" else None
                weak, quantum = classify_algorithm(algorithm) if algorithm else (False, False)
                self.sites.append(
                    CryptoSite(
                        site_id=node_id(kind, self.file, line, col, name),
                        file=self.file,
                        line=line,
                        col=col,
                        qualified_name=name,
                        kind=kind,
                        algorithm=algorithm,
                        module=self.module,
                        weak=weak,
                        quantum_vulnerable=quantum,
                        enclosing_function=self._enclosing,
                        parent_site_id=site_id,
                    )
                )

    def _classify(self, node: cst.CSTNode) -> tuple[str, str] | None:
        """Return ``(kind, name)`` if this node is itself a selector, else ``None``."""
        if isinstance(node, cst.Call):
            if self._qualified_names(node.func) & _CONFIG_QUALIFIED_NAMES:
                return ("config_read", _expr_name(node.func))
            if _root_name(node.func) in _CONFIG_NAME_HINTS:
                return ("config_read", _expr_name(node.func))
            # An algorithm constructor such as hashes.SHA256() reads as a literal.
            name = _expr_name(node.func)
            if _algorithm_from_name(name):
                return ("algo_literal", name)
            return None

        if isinstance(node, cst.Subscript):
            if (
                self._qualified_names(node.value) & {"os.environ"}
                or _root_name(node.value) in _CONFIG_NAME_HINTS
            ):
                return ("config_read", _expr_name(node.value))
            return None

        if isinstance(node, cst.Attribute):
            name = _expr_name(node)
            if _root_name(node) in _CONFIG_NAME_HINTS:
                return ("config_read", name)
            if _algorithm_from_name(name):
                return ("algo_literal", name)
            return None

        if isinstance(node, cst.Name):
            return ("algo_literal", node.value) if _algorithm_from_name(node.value) else None

        if isinstance(node, cst.SimpleString):
            literal = node.raw_value
            return ("algo_literal", literal) if _algorithm_from_name(literal) else None

        return None

    def _walk_selectors(self, node: cst.CSTNode) -> Iterator[tuple[str, str, cst.CSTNode]]:
        """Yield ``(kind, name, node)`` for selector expressions inside a crypto call.

        Recursion is generic over ``children`` rather than an enumerated list of
        expression types. Hand-enumerating was missing real shapes — ``os.getenv(...)
        .encode()`` hides the config read in the *callee* of an outer call, not in its
        arguments — and every omission is a silent false negative.

        A node that classifies is a leaf: descending further would double-count
        ``hashes.SHA256()`` as both a call and an attribute.
        """
        classification = self._classify(node)
        if classification is not None:
            yield (classification[0], classification[1], node)
            return

        for child in node.children:
            yield from self._walk_selectors(child)


def _expr_name(node: cst.CSTNode) -> str:
    """Render a dotted expression back to source text, best effort."""
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        return f"{_expr_name(node.value)}.{node.attr.value}"
    return type(node).__name__


def _root_name(node: cst.CSTNode) -> str:
    """The leftmost identifier of a dotted expression."""
    while isinstance(node, cst.Attribute):
        node = node.value
    return node.value.lower() if isinstance(node, cst.Name) else ""


# ---------------------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------------------


def detect_file(path: Path, root: Path, settings: Settings | None = None) -> DetectionResult:
    """Detect crypto usage in one file. Never raises for target-code problems."""
    cfg = settings or get_settings()
    result = DetectionResult()
    # walk_repository yields resolved paths; normalise the root so a caller passing a
    # relative one still produces repo-relative citations rather than an exception.
    root = root.resolve()
    path = path.resolve()
    rel = str(path.relative_to(root))

    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.unparseable.append(
            UnparseableFile(file=rel, reason=f"unreadable: {type(exc).__name__}")
        )
        return result

    try:
        with _parse_timeout(cfg.analysis.parse_timeout_s):
            module = cst.parse_module(source)
            wrapper = MetadataWrapper(module, unsafe_skip_copy=True)
            visitor = _CryptoVisitor(file=rel, module=module_name(path, root))
            wrapper.visit(visitor)
    except ParseTimeout as exc:
        result.unparseable.append(UnparseableFile(file=rel, reason=str(exc)))
        return result
    except cst.ParserSyntaxError as exc:
        # Python 2, a newer grammar than LibCST supports, or genuinely broken source.
        result.unparseable.append(UnparseableFile(file=rel, reason=f"syntax error: {exc.message}"))
        return result
    except RecursionError:
        result.unparseable.append(UnparseableFile(file=rel, reason="expression nested too deeply"))
        return result
    except Exception as exc:  # pragma: no cover - defensive
        # A parser bug on hostile input must degrade one file, never the whole job.
        result.unparseable.append(UnparseableFile(file=rel, reason=f"{type(exc).__name__}"))
        return result

    result.sites.extend(visitor.sites)
    result.files_scanned = 1
    return result


def detect_repository(
    files: list[Path], root: Path, settings: Settings | None = None
) -> DetectionResult:
    """Detect across a file list, aggregating sites and unparseable records (PROC-02).

    Unparseable files are excluded from the denominator but **not** from the report: a
    silently dropped file is an unmeasured false negative.
    """
    cfg = settings or get_settings()
    combined = DetectionResult()

    for path in files:
        one = detect_file(path, root, cfg)
        combined.sites.extend(one.sites)
        combined.unparseable.extend(one.unparseable)
        combined.files_scanned += one.files_scanned

    combined.sites.sort(key=lambda s: (s.file, s.line, s.col, s.kind, s.qualified_name))
    combined.unparseable.sort(key=lambda u: u.file)
    return combined
