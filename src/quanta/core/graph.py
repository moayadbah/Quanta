"""Cryptographic Dependency Graph construction (§5.3.2).

The CDG is the artifact no existing tool emits, and the reason Quanta can answer *how
hard is this to change* rather than merely *where is the crypto*.

Node kinds: ``module``, ``function``, ``crypto_call``, ``algo_literal``, ``config_read``.
Edge kinds and their honest confidence labels:

===============  ==========  ==================================================
kind             confidence  meaning
===============  ==========  ==================================================
``binding``      high        scope containment, from LibCST's own scope analysis
``value_flow``   high        a selector feeding the call it configures
``import``       high        module depends on module
``call``         **low**     one-hop callee resolution — an *approximation*
===============  ==========  ==================================================

Edge direction is toward the cryptography, so ``nx.ancestors(G, crypto_node)`` is exactly
the blast radius: everything that reaches this call site and might have to change with it.

The honest boundary, restated because it bounds what the score may claim: **name binding
is free from LibCST; value flow across function and module boundaries is not.** Every
``call`` edge is therefore ``confidence: "low"``, enforced by the model layer rather than
by convention, and unresolvable or ambiguous callees are dropped rather than guessed.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import networkx as nx

from quanta.core.detect import DetectionResult

#: NetworkX renamed the node-link edge key; pinning it keeps ``cdg.json`` stable across
#: library upgrades, which NFR-03 and DoD-C3 both depend on.
_EDGES_KEY = "links"


@dataclass
class ResolutionStats:
    """What one-hop callee resolution managed, and what it refused to guess.

    These numbers are the honest counterpart to the CDG's ``call`` edges. §5.3.2 forbids
    guessing an unresolvable or ambiguous target, and RR-2 requires the resulting
    under-reporting be *measured and published* rather than concealed — so the analyzer
    has to count its own misses, not just its hits.
    """

    callees_seen: int = 0
    callees_resolved: int = 0
    callees_ambiguous: int = 0
    callees_unresolved: int = 0
    imports_resolved: int = 0
    imports_external: int = 0


def _nid(kind: str, name: str) -> str:
    digest = hashlib.sha256(f"{kind}|{name}".encode()).hexdigest()[:16]
    return f"{kind}-{digest}"


def _suffix_index(qualnames: list[str]) -> dict[str, set[str]]:
    """Map every dotted suffix of each qualified name to the names that end with it.

    Used to bind a callee such as ``.crypto_facade.digest`` — which is what a relative
    import resolves to — onto the defined function ``src.crypto_facade.digest``.
    """
    index: dict[str, set[str]] = defaultdict(set)
    for qualname in qualnames:
        parts = qualname.split(".")
        for i in range(len(parts)):
            index[".".join(parts[i:])].add(qualname)
    return index


def build_cdg(detection: DetectionResult, stats: ResolutionStats | None = None) -> nx.DiGraph:
    """Assemble the CDG from a :class:`DetectionResult`.

    Construction order is sorted at every step so the emitted node and edge lists — and
    therefore the bytes of ``cdg.json`` — are identical across runs.

    ``stats`` is an optional out-parameter filled with resolution counters. It is kept out
    of the return value, and out of ``cdg.json``, so adding this instrumentation changes
    no artifact and cannot perturb NFR-03.
    """
    graph: nx.DiGraph = nx.DiGraph()
    counters = stats if stats is not None else ResolutionStats()

    module_files: dict[str, str] = {}
    for record in detection.functions:
        module_files.setdefault(record.module, record.file)
    for site in detection.sites:
        module_files.setdefault(site.module, site.file)
    for module in detection.modules:
        module_files.setdefault(module, "")

    # -- module nodes -------------------------------------------------------------
    module_nodes: dict[str, str] = {}
    for module in sorted(module_files):
        node = _nid("module", module)
        module_nodes[module] = node
        graph.add_node(
            node,
            kind="module",
            file=module_files[module],
            line=0,
            col=0,
            qualified_name=module,
            module=module,
            source="static",
            algorithm=None,
        )

    # -- function nodes -----------------------------------------------------------
    function_nodes: dict[str, str] = {}
    for record in sorted(detection.functions, key=lambda f: (f.qualname, f.line)):
        if record.qualname in function_nodes:
            continue  # a redefinition; one scope node is enough
        node = _nid("function", record.qualname)
        function_nodes[record.qualname] = node
        graph.add_node(
            node,
            kind="function",
            file=record.file,
            line=record.line,
            col=record.col,
            qualified_name=record.qualname,
            module=record.module,
            source="static",
            algorithm=None,
        )
        if record.module in module_nodes:
            graph.add_edge(module_nodes[record.module], node, kind="binding", confidence="high")

    # -- site nodes ---------------------------------------------------------------
    for site in detection.sites:
        graph.add_node(
            site.site_id,
            kind=site.kind,
            file=site.file,
            line=site.line,
            col=site.col,
            qualified_name=site.qualified_name,
            module=site.module,
            source=site.source,
            algorithm=site.algorithm,
        )

        # Attach each site to the tightest enclosing scope we know about.
        owner: str | None = None
        if site.enclosing_function:
            owner = function_nodes.get(f"{site.module}.{site.enclosing_function}")
        if owner is None:
            owner = module_nodes.get(site.module)
        if owner is not None:
            graph.add_edge(owner, site.site_id, kind="binding", confidence="high")

    # -- selector value flow ------------------------------------------------------
    for site in detection.sites:
        if site.parent_site_id and graph.has_node(site.parent_site_id):
            # The literal or config read *selects* the algorithm the call will use, so
            # flow runs from the selector into the call.
            graph.add_edge(site.site_id, site.parent_site_id, kind="value_flow", confidence="high")

    # -- import edges -------------------------------------------------------------
    module_index = _suffix_index(sorted(module_nodes))
    for imp in detection.imports:
        target_name = imp.target.lstrip(".")
        module_candidates = module_index.get(target_name, set())
        if len(module_candidates) != 1:
            # Third-party or ambiguous. Counted, because "how much of this repository's
            # dependency surface is external?" is a real question the trace can answer.
            counters.imports_external += 1
            continue
        resolved = next(iter(module_candidates))
        if resolved == imp.module:
            continue
        counters.imports_resolved += 1
        graph.add_edge(
            module_nodes[imp.module], module_nodes[resolved], kind="import", confidence="high"
        )

    # -- one-hop call edges (always low confidence) --------------------------------
    function_index = _suffix_index(sorted(function_nodes))
    for call in detection.calls:
        counters.callees_seen += 1
        callee = call.callee.lstrip(".")
        call_candidates = function_index.get(callee, set())
        if len(call_candidates) != 1:
            # Zero candidates means the callee is third-party or unresolvable; more than
            # one means the name is ambiguous. §5.3.2 forbids guessing in either case.
            if call_candidates:
                counters.callees_ambiguous += 1
            else:
                counters.callees_unresolved += 1
            continue
        counters.callees_resolved += 1
        target_qualname = next(iter(call_candidates))
        caller = function_nodes.get(call.caller_qualname) or module_nodes.get(call.caller_module)
        target_node = function_nodes[target_qualname]
        if caller is None or caller == target_node:
            continue
        graph.add_edge(caller, target_node, kind="call", confidence="low")

    return graph


# ---------------------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------------------


def to_node_link(graph: nx.DiGraph) -> dict[str, Any]:
    """Serialise to NetworkX node-link form with sorted nodes and edges (DoD-C3)."""
    data: dict[str, Any] = nx.node_link_data(graph, edges=_EDGES_KEY)
    data["nodes"] = sorted(data["nodes"], key=lambda n: str(n["id"]))
    data[_EDGES_KEY] = sorted(
        data[_EDGES_KEY],
        key=lambda e: (str(e["source"]), str(e["target"]), str(e.get("kind", ""))),
    )
    return data


def from_node_link(data: dict[str, Any]) -> nx.DiGraph:
    """Inverse of :func:`to_node_link`; ``cdg.json`` must survive this round trip."""
    graph: nx.DiGraph = nx.node_link_graph(data, directed=True, edges=_EDGES_KEY)
    return graph


# ---------------------------------------------------------------------------------------
# Metrics consumed by the score
# ---------------------------------------------------------------------------------------


def crypto_nodes(graph: nx.DiGraph) -> list[str]:
    return sorted(n for n, d in graph.nodes(data=True) if d.get("kind") == "crypto_call")


def module_nodes_of(graph: nx.DiGraph) -> list[str]:
    return sorted(n for n, d in graph.nodes(data=True) if d.get("kind") == "module")


def blast_radius(graph: nx.DiGraph, node: str) -> int:
    """Number of graph ancestors — everything that reaches this crypto site.

    This is E2's refusal criterion (``blast_radius_max``) and the raw input to
    ``f_propagation``.
    """
    return len(nx.ancestors(graph, node))


def isolation_cut_size(graph: nx.DiGraph) -> tuple[int, bool]:
    """Minimum number of nodes whose removal decouples cryptography from the rest.

    This operationalises "does an insulation layer exist?" — a facade shows up as a small
    cut, because deleting the facade disconnects everything else from the primitives.

    ``nx.minimum_node_cut`` takes single endpoints, so a synthetic super-source over
    non-crypto nodes and super-sink over crypto nodes are added first.

    Returns ``(cut_size, disconnected)``. The flag matters: when cryptography is already
    unreachable from the rest of the graph the cut is 0, which the ``1/(1+cut)``
    normalisation scores as *perfectly isolated*. That is arguably right — nothing depends
    on the crypto — but it is not what §5.3.3's "no cut → 0" phrasing suggests, so the
    caller is told which case it is rather than being handed an ambiguous 0.
    """
    crypto = set(crypto_nodes(graph))
    if not crypto:
        return (0, True)

    others = [n for n in graph.nodes if n not in crypto]
    if not others:
        return (0, True)

    # Undirected: an insulation layer insulates regardless of edge direction.
    working = nx.Graph()
    working.add_nodes_from(graph.nodes)
    working.add_edges_from((u, v) for u, v in graph.edges if u != v)

    source, sink = "__quanta_source__", "__quanta_sink__"
    working.add_node(source)
    working.add_node(sink)
    for n in sorted(others):
        working.add_edge(source, n)
    for n in sorted(crypto):
        working.add_edge(n, sink)

    try:
        cut = nx.minimum_node_cut(working, source, sink)
    except (nx.NetworkXError, nx.NetworkXUnbounded):
        return (0, True)

    if not cut:
        return (0, True)
    return (len(cut), False)
