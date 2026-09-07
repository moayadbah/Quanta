"""Self-contained HTML report with an inline, deterministic CDG figure.

Three properties are load-bearing (PROC-07, NFR-07, DoD-C5, T5):

* **Self-contained.** Inline SVG, inline CSS, zero external requests. ``report.html``
  opens from ``file://`` with no server and no network.
* **Deterministic.** Layout is a pure function of the sorted node and edge lists, so the
  same provenance triple yields byte-identical output (ADR-018, NFR-03).
* **Safe.** Repository *content* is never embedded — only file paths, line numbers and
  qualified names, each passed through :func:`safe_text` before rendering. The figure is
  drawn from our own graph data, never from repository bytes, and Jinja2 autoescaping is
  on for every interpolated value.

The report renders attacker-controlled identifiers: a repository can contain a file named
``<script>alert(1)</script>.py``. That is the T5 stored-XSS path, and it is closed by
escaping plus a strict CSP on the served response.
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

import networkx as nx
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from markupsafe import Markup

from quanta.config import Settings, get_settings
from quanta.core.models import AnalysisMeta, ScoreReport
from quanta.resources import asset_path

_TEMPLATE_DIR = asset_path("templates")

#: Everything outside this class is replaced before a value reaches the page. Deliberately
#: narrow: identifiers, paths and dotted names need nothing else.
_UNSAFE = re.compile(r"[^A-Za-z0-9 ._/:<>@+\-\[\](),#]")

#: Beyond this the figure stops being readable and starts being a wall. Excess nodes are
#: declared in the caption rather than dropped silently (§11.3 rule 3).
MAX_RENDER_NODES = 80

_KIND_COLUMNS = ("module", "function", "crypto_call", "algo_literal", "config_read")
_KIND_FILL = {
    "module": "#3b5b8c",
    "function": "#4a7c59",
    "crypto_call": "#a33b3b",
    "algo_literal": "#8a6d99",
    "config_read": "#6d6a8a",
}
_EDGE_STROKE = {
    "binding": "#8b93a3",
    "value_flow": "#4a7c59",
    "import": "#3b5b8c",
    "call": "#b08a3c",
}

_COL_WIDTH = 250
_ROW_HEIGHT = 34
_NODE_W = 200
_NODE_H = 22
_PAD = 24

#: Headers the web tier must set when serving ``report.html`` (§7.3 T5, DoD-C5).
#:
#: ``default-src 'none'`` is the substantive control: the report needs no scripts, no
#: fetches and no external anything, so the page is permitted none. Escaping is the first
#: line of defence and this is the second — if an identifier ever slipped through, it
#: still could not execute or exfiltrate. Defined here, beside the renderer, so the
#: contract lives with the artifact rather than in a route handler.
#:
#: **Framing uses ``frame-ancestors``, not ``X-Frame-Options``.** §7.3 names both
#: ``X-Frame-Options: SAMEORIGIN`` *and* embedding the report in a ``sandbox`` iframe, and
#: those two controls are mutually exclusive: a sandboxed frame has an **opaque** origin,
#: so ``SAMEORIGIN`` can never match and the browser blanks the report. Verified in a
#: browser, not deduced.
#:
#: ``frame-ancestors 'self'`` restricts the same thing but tests the *embedding* page's
#: origin rather than the frame's own, so it is unaffected by the opaque origin and lets
#: the sandbox stay at maximum strength (no ``allow-same-origin``, no ``allow-scripts``).
#: That combination is strictly stronger than the spec's pairing, and CSP ``frame-ancestors``
#: formally obsoletes ``X-Frame-Options`` in any case.
REPORT_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def safe_text(value: object, limit: int = 200) -> str:
    """Reduce a value to the safe character class and bound its length (T5)."""
    text = str(value)
    cleaned = _UNSAFE.sub("�", text)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


# ---------------------------------------------------------------------------------------
# Deterministic SVG
# ---------------------------------------------------------------------------------------


def _select_nodes(graph: nx.DiGraph) -> tuple[list[str], int]:
    """Choose which nodes to draw, preferring cryptography and what touches it."""
    all_nodes = sorted(graph.nodes)
    if len(all_nodes) <= MAX_RENDER_NODES:
        return all_nodes, 0

    keep: list[str] = []
    crypto = [n for n in all_nodes if graph.nodes[n].get("kind") == "crypto_call"]
    keep.extend(crypto)

    # One hop out from cryptography, in both directions — that is the interesting part.
    neighbours: set[str] = set()
    for node in crypto:
        neighbours |= set(graph.predecessors(node)) | set(graph.successors(node))
    keep.extend(sorted(n for n in neighbours if n not in set(keep)))

    for node in all_nodes:
        if len(keep) >= MAX_RENDER_NODES:
            break
        if node not in set(keep):
            keep.append(node)

    selected = sorted(keep[:MAX_RENDER_NODES])
    return selected, len(all_nodes) - len(selected)


def render_cdg_svg(graph: nx.DiGraph) -> tuple[Markup, int]:
    """Render the CDG as inline SVG. Returns ``(markup, omitted_node_count)``.

    Layout is a fixed-column arrangement keyed on node kind, with rows assigned by sorted
    order. No randomness, no iteration-order dependence, no external layout engine — the
    same graph always produces the same bytes.
    """
    selected, omitted = _select_nodes(graph)
    if not selected:
        return Markup('<p class="empty">No cryptographic dependencies detected.</p>'), 0

    columns: dict[str, list[str]] = {kind: [] for kind in _KIND_COLUMNS}
    for node in selected:
        kind = str(graph.nodes[node].get("kind", "module"))
        columns.setdefault(kind, []).append(node)

    position: dict[str, tuple[int, int]] = {}
    for col_index, kind in enumerate(_KIND_COLUMNS):
        for row_index, node in enumerate(sorted(columns.get(kind, []))):
            x = _PAD + col_index * _COL_WIDTH
            y = _PAD + row_index * _ROW_HEIGHT
            position[node] = (x, y)

    rows = max((len(v) for v in columns.values()), default=1)
    width = _PAD * 2 + len(_KIND_COLUMNS) * _COL_WIDTH
    height = _PAD * 2 + max(rows, 1) * _ROW_HEIGHT

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" '
        f'aria-label="Cryptographic Dependency Graph">'
    ]

    # Edges first so nodes draw over them.
    drawn = set(position)
    for source, target, data in sorted(
        graph.edges(data=True), key=lambda e: (str(e[0]), str(e[1]), str(e[2].get("kind", "")))
    ):
        if source not in drawn or target not in drawn:
            continue
        x1, y1 = position[source]
        x2, y2 = position[target]
        kind = str(data.get("kind", "binding"))
        stroke = _EDGE_STROKE.get(kind, "#8b93a3")
        # Low-confidence edges are dashed. The distinction between measured and estimated
        # propagation is a research claim, so it must be visible, not buried in JSON.
        dash = ' stroke-dasharray="4 3"' if data.get("confidence") == "low" else ""
        parts.append(
            f'<line x1="{x1 + _NODE_W}" y1="{y1 + _NODE_H // 2}" '
            f'x2="{x2}" y2="{y2 + _NODE_H // 2}" '
            f'stroke="{stroke}" stroke-width="1"{dash} opacity="0.55"/>'
        )

    for node in selected:
        x, y = position[node]
        attrs = graph.nodes[node]
        kind = str(attrs.get("kind", "module"))
        fill = _KIND_FILL.get(kind, "#555")
        label = safe_text(attrs.get("qualified_name", node), limit=34)
        line_no = attrs.get("line", 0)
        suffix = f":{line_no}" if isinstance(line_no, int) and line_no > 0 else ""
        title = safe_text(f"{attrs.get('file', '')}{suffix} {attrs.get('qualified_name', '')}")
        parts.append(
            f"<g><title>{html.escape(title)}</title>"
            f'<rect x="{x}" y="{y}" width="{_NODE_W}" height="{_NODE_H}" rx="4" '
            f'fill="{fill}" opacity="0.9"/>'
            f'<text x="{x + 8}" y="{y + 15}" font-family="ui-monospace,monospace" '
            f'font-size="11" fill="#ffffff">{html.escape(label)}</text></g>'
        )

    parts.append("</svg>")
    # S704: Markup bypasses Jinja2 autoescaping, so this is the one place in the report
    # where escaping is our responsibility rather than the template engine's. Every value
    # interpolated above is either a numeric coordinate we computed, a colour from a fixed
    # table, or a string passed through safe_text() *and* html.escape(). No repository
    # bytes reach this string — the figure is drawn from our own graph data (T5).
    return Markup("".join(parts)), omitted  # noqa: S704


def _legend() -> list[dict[str, str]]:
    return [
        {"label": "module", "color": _KIND_FILL["module"]},
        {"label": "function", "color": _KIND_FILL["function"]},
        {"label": "crypto call", "color": _KIND_FILL["crypto_call"]},
        {"label": "algorithm literal", "color": _KIND_FILL["algo_literal"]},
        {"label": "config read", "color": _KIND_FILL["config_read"]},
    ]


# ---------------------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------------------


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"], default_for_string=True),
        # StrictUndefined: a missing template variable must fail the render rather than
        # silently produce a blank cell in a report someone will act on.
        undefined=StrictUndefined,
    )


def render_report(
    score: ScoreReport,
    graph: nx.DiGraph,
    meta: AnalysisMeta,
    settings: Settings | None = None,
) -> str:
    """Render the canonical, self-contained ``report.html``."""
    cfg = settings or get_settings()
    svg, omitted = render_cdg_svg(graph)

    factor_titles = {
        "call_sites": "Call sites",
        "isolation_layer": "Isolation layer",
        "selection_source": "Algorithm selection",
        "propagation_depth": "Propagation depth",
    }

    context: dict[str, Any] = {
        "score": score,
        "meta": meta,
        "svg": svg,
        "omitted_nodes": omitted,
        "legend": _legend(),
        "factor_titles": factor_titles,
        "renderer": cfg.report.renderer,
        "safe": safe_text,
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "low_confidence_edges": sum(
            1 for _, _, d in graph.edges(data=True) if d.get("confidence") == "low"
        ),
    }
    return _environment().get_template("report.html.j2").render(**context)


def write_report(path: Path, html_text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_text, encoding="utf-8")
