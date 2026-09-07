"""Demo data: bilingual copy, the glossary, and the three measured vault variants.

The variant figures are **computed at request time from the real analyzer**, not read from
a table someone typed. If a change to the scorer moves the numbers, the demo moves with
them — the alternative is a walkthrough that confidently states figures the tool no longer
produces, which is the exact failure mode a defence cannot survive.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from quanta.core.analyze import analyze_path
from quanta.core.graph import crypto_surface, isolation_cut_size
from quanta.core.models import Provenance
from quanta.resources import asset_path
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version

DEMO_ROOT = asset_path("demo")
CONTENT_PATH = DEMO_ROOT / "content.json"
GLOSSARY_PATH = DEMO_ROOT / "glossary.json"
VARIANT_ROOT = DEMO_ROOT / "repos"

#: Presentation order. Also the order act 4 animates them in.
VARIANT_ORDER = ("vault-scattered", "vault-facade", "vault-configured")


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as fh:
        payload: dict[str, Any] = json.load(fh)
    return payload


@lru_cache(maxsize=1)
def load_content() -> dict[str, Any]:
    return _load(CONTENT_PATH)


@lru_cache(maxsize=1)
def load_glossary() -> dict[str, Any]:
    return {k: v for k, v in _load(GLOSSARY_PATH).items() if not k.startswith("_")}


@lru_cache(maxsize=1)
def variant_report() -> dict[str, Any]:
    """Analyse all three variants and return the figures act 4 draws.

    Cached for the process lifetime: the sources are committed and do not change while the
    server runs, and re-analysing on every navigation would make the act feel sluggish.
    """
    variants = []
    for name in VARIANT_ORDER:
        root = VARIANT_ROOT / name
        if not root.is_dir():
            continue

        provenance = Provenance(
            repo=f"demo/{name}",
            commit_sha="0" * 40,
            analyzer_version=analyzer_version(),
            crypto_ruleset_version=CRYPTO_RULESET_VERSION,
        )
        outcome = analyze_path(root, provenance)
        graph = outcome.graph
        cut, _disconnected = isolation_cut_size(graph)

        variants.append(
            {
                "slug": name,
                "agility_score": outcome.score.agility_score,
                "cut": cut,
                "sites": len(outcome.detection.crypto_calls),
                "modules_with_crypto": len({s.module for s in outcome.detection.crypto_calls}),
                "modules": outcome.detection.files_scanned,
                "surface_nodes": len(crypto_surface(graph)),
                "factors": {
                    key: {
                        "normalised": factor.normalised,
                        "weight": factor.weight,
                        "contribution": factor.contribution,
                    }
                    for key, factor in outcome.score.factors.items()
                },
                "graph": _mini_graph(graph),
            }
        )

    return {"variants": variants}


def _mini_graph(graph: Any) -> dict[str, Any]:
    """A small, layout-ready projection of the CDG for the act 4 figure.

    Only modules, functions and the cryptographic surface — the demo graph must stay
    legible on a projector, and the full CDG is hundreds of nodes. ``cut`` marks the nodes
    ``isolation_cut_size`` actually returns, so the animation removes the true cut rather
    than an illustrative one.
    """
    import networkx as nx

    crypto = set(crypto_surface(graph))
    others = [n for n in graph.nodes if n not in crypto]

    cut_nodes: set[str] = set()
    if crypto and others:
        working = nx.Graph()
        working.add_nodes_from(graph.nodes)
        working.add_edges_from((u, v) for u, v in graph.edges if u != v)
        source, sink = "__s__", "__t__"
        for n in sorted(others):
            working.add_edge(source, n)
        for n in sorted(crypto):
            working.add_edge(n, sink)
        try:
            cut_nodes = set(nx.minimum_node_cut(working, source, sink))
        except (nx.NetworkXError, nx.NetworkXUnbounded):
            cut_nodes = set()

    # Keep the figure legible on a projector: the cryptographic surface, whatever touches
    # it directly, and the modules those live in. Unrelated functions are dropped — they
    # are real but they are not what act 4 is about, and 50 nodes reads as noise.
    undirected = nx.Graph()
    undirected.add_nodes_from(graph.nodes)
    undirected.add_edges_from((u, v) for u, v in graph.edges if u != v)

    keep = set(crypto) | cut_nodes
    for node in list(crypto):
        keep |= set(undirected.neighbors(node))
    keep |= {
        n
        for n in graph.nodes
        if graph.nodes[n].get("kind") == "module"
        and any(graph.nodes[k].get("module") == graph.nodes[n].get("module") for k in keep)
    }

    nodes = [
        {
            "id": node,
            "kind": str(data.get("kind")),
            "label": _short_label(str(data.get("qualified_name", ""))),
            "in_cut": node in cut_nodes,
            "crypto": node in crypto,
        }
        for node, data in sorted(graph.nodes(data=True), key=lambda item: str(item[0]))
        if node in keep
    ]
    known = {n["id"] for n in nodes}
    edges = [
        {
            "source": u,
            "target": v,
            "kind": str(d.get("kind")),
            "confidence": str(d.get("confidence")),
        }
        for u, v, d in sorted(graph.edges(data=True), key=lambda e: (str(e[0]), str(e[1])))
        if u in known and v in known
    ]
    return {"nodes": nodes, "edges": edges, "cut": sorted(cut_nodes)}


def _short_label(qualified_name: str) -> str:
    """Last two dotted segments — enough to identify a node, short enough to project."""
    parts = qualified_name.split(".")
    return ".".join(parts[-2:]) if len(parts) > 2 else qualified_name


#: The ADR-019 beat: the same inputs hashed two ways, against the published vector.
def xwing_evidence() -> dict[str, Any]:
    """Recompute the combiner comparison live, from the committed draft-10 vector.

    Not a screenshot and not a stored string: the demo asserts that our order matches the
    published vector and the documentation's order does not, so it should demonstrate that
    by actually hashing.
    """
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    from quanta.shim import _quanta_hybrid as xwing

    vectors_path = asset_path("tests/fixtures/xwing_draft10_vectors.json")
    if not vectors_path.is_file():
        return {}

    with vectors_path.open(encoding="utf-8") as fh:
        vector = json.load(fh)[0]

    seed = bytes.fromhex(vector["seed"])
    ciphertext = bytes.fromhex(vector["ct"])
    expected = vector["ss"]

    sk_m, sk_x, pk_x = xwing._expand_decapsulation_key(seed)
    ct_m, ct_x = ciphertext[:1088], ciphertext[1088:]
    ss_m = sk_m.decapsulate(ct_m)
    ss_x = sk_x.exchange(X25519PublicKey.from_public_bytes(ct_x))
    label = xwing._XWING_LABEL

    draft_order = hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + label).hexdigest()
    document_order = hashlib.sha3_256(label + ss_m + ss_x + ct_x + pk_x).hexdigest()

    return {
        "published": expected,
        "draft_order": draft_order,
        "document_order": document_order,
        "draft_matches": draft_order == expected,
        "document_matches": document_order == expected,
    }
