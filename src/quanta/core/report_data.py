"""One description of a finished analysis, rendered twice: ``report.html`` and the PDF.

Both documents read the same dictionary, so they cannot disagree, and every label comes
from ``content/site.json`` (English), the file the web product reads, so the report and
the page use the same words. Order follows what a reader needs: readiness first, then
the findings behind it, the proposed changes, the deadlines, and last the method.
"""

from __future__ import annotations

import json
from collections import Counter
from functools import lru_cache
from typing import Any

from quanta.core.coverage import migrations
from quanta.core.readiness import standards
from quanta.resources import asset_path

STATUSES = ("vulnerable", "weak", "review", "pq", "safe")
ACTIONABLE = {"vulnerable", "weak", "review"}
#: Rows shown in the findings table; the complete list is in findings.json.
FINDING_ROWS = 80


@lru_cache(maxsize=1)
def _strings() -> dict[str, dict[str, str]]:
    payload = json.loads(asset_path("content/site.json").read_text(encoding="utf-8"))
    table: dict[str, dict[str, str]] = payload["strings"]
    return table


def en(key: str, **values: Any) -> str:
    """The English string for ``key`` with ``{placeholders}`` filled, or the key itself."""
    text = _strings().get(key, {}).get("en", key)
    for name, value in values.items():
        text = text.replace("{" + name + "}", str(value))
    return text


def _source(source_id: str) -> dict[str, str]:
    source = standards()["sources"].get(source_id, {})
    return {
        "id": source_id,
        "title": en(f"src.{source_id}"),
        "publisher": str(source.get("publisher", "")),
        "url": str(source.get("url", "")),
        "status": str(source.get("status", "")),
    }


def build(
    *,
    score: dict[str, Any],
    meta: dict[str, Any],
    readiness: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    fixes: dict[str, Any],
) -> dict[str, Any]:
    provenance = score.get("provenance", {})
    shipped = [f for f in findings if f.get("role") == "source"]
    other = [f for f in findings if f.get("role") != "source"]

    def status(f: dict[str, Any]) -> str:
        return str((f.get("readiness") or {}).get("status", "safe"))

    patched = {(f["path"], c["line"]) for f in fixes.get("files", []) for c in f["changes"]}
    refused = {(s["path"], s["line"]) for s in fixes.get("skipped", [])}
    guided = {(s["path"], s["line"]): g["id"] for g in fixes.get("guides", []) for s in g["sites"]}

    def entry(f: dict[str, Any]) -> str:
        key = (f["file"], f["line"])
        if key in patched:
            return en("report.entry.patch")
        if key in refused:
            return en("report.entry.refused")
        if key in guided:
            return en("report.entry.guide")
        return ""

    rows = [
        {
            "where": f"{f['file']}:{f['line']}",
            "name": str(f.get("name", "")),
            "algorithm": str(f.get("algorithm") or ", ".join(f.get("algorithms") or [])),
            "status": status(f),
            "status_label": en(f"st.{status(f)}"),
            "entry": entry(f),
        }
        for f in shipped
        if status(f) in ACTIONABLE
    ]
    order = {s: i for i, s in enumerate(STATUSES)}
    rows.sort(key=lambda r: (order[r["status"]], r["where"]))

    verdict = (readiness or {}).get("verdict", "")
    counts = (readiness or {}).get("counts", {})
    tally = {s: int(counts.get(s, 0)) for s in STATUSES}
    sites = int(counts.get("sites", 0))
    implements = sorted(
        {str(f.get("algorithm")) for f in shipped if f.get("form") == "implementation"}
    )
    other_actionable = Counter(status(f) for f in other if status(f) in ACTIONABLE)

    actions = []
    for rank, action in enumerate((readiness or {}).get("actions", []), 1):
        by = action.get("by")
        in_force = bool(action.get("in_force"))
        overdue = in_force or bool(by and readiness and by <= readiness.get("reference_year", 0))
        actions.append(
            {
                "rank": rank,
                "title": en(f"action.{action['id']}.title"),
                "body": en(f"action.{action['id']}.body"),
                "when": (
                    en("ready.in_force")
                    if in_force
                    else en("ready.overdue_since", year=by)
                    if overdue
                    else en("ready.by", year=by)
                    if by
                    else en("ready.no_date")
                ),
                "overdue": overdue,
                "sites": action.get("sites", 0),
                "sites_label": en("ready.sites", n=action.get("sites", 0)),
                "sources": [_source(s) for s in action.get("sources", [])],
            }
        )

    for a in actions:
        a["sources_line"] = sources_line(a["sources"])

    milestones = [
        m for m in (readiness or {}).get("milestones", []) if m.get("state") in {"overdue", "due"}
    ]
    milestones.sort(
        key=lambda m: (
            0 if m.get("in_force") else m.get("year") or 9999,
            m.get("year") or 0,
            m["id"],
        )
    )
    deadlines = [
        {
            "framework": en(f"fw.{m['framework']}"),
            "rule": en(f"ms.{m['id']}"),
            "year": (
                en("readiness.after", year=m["year"])
                if m.get("in_force") and m.get("year")
                else en("readiness.in_force")
                if m.get("in_force")
                else m.get("year") or en("readiness.any_date")
            ),
            "sites": m.get("sites", 0),
            "state": m["state"],
            "state_label": en(f"ms.state.{m['state']}"),
            "source": _source(m["source"]),
        }
        for m in milestones
    ]
    clear = sum(1 for m in (readiness or {}).get("milestones", []) if m.get("state") == "clear")

    catalogue = migrations()
    patches = [
        {
            "where": f"{f['path']}:{c['line']}",
            "before": c.get("line_before") or c.get("before", ""),
            "after": c.get("line_after") or c.get("after", ""),
        }
        for f in fixes.get("files", [])
        for c in f["changes"]
    ]
    guides = [
        {
            "title": en(f"guide.{g['id']}.title"),
            "body": en(f"guide.{g['id']}.body"),
            "to": catalogue.get(g["id"], {}).get("to", ""),
            "example": catalogue.get(g["id"], {}).get("example", ""),
            "count": len(g["sites"]),
            "sites": [f"{s['path']}:{s['line']}" for s in g["sites"]],
            "sources": [_source(s) for s in catalogue.get(g["id"], {}).get("sources", [])],
        }
        for g in fixes.get("guides", [])
    ]
    for g in guides:
        g["sources_line"] = sources_line(g["sources"])
        g["sites_line"] = sites_line(g["sites"], g["count"])
        g["target"] = en("doc.target", to=g["to"])
        g["sites_label"] = en("ready.sites", n=g["count"])
    refusals = [
        {
            "where": f"{s['path']}:{s['line']}",
            "title": en(f"refusal.{s['code']}.title")
            if f"refusal.{s['code']}.title" in _strings()
            else en("refusal.other.title"),
            "detail": en(f"refusal.{s['code']}.body")
            if f"refusal.{s['code']}.body" in _strings()
            else s.get("detail", ""),
        }
        for s in fixes.get("skipped", [])
    ]
    coverage = score.get("coverage", {})
    data: dict[str, Any] = {
        "repo": provenance.get("repo", ""),
        "commit": str(provenance.get("commit_sha", ""))[:12],
        "real_commit": not set(str(provenance.get("commit_sha", ""))) <= {"0"},
        "date": str(meta.get("finished_at", ""))[:10],
        "analyzer": provenance.get("analyzer_version", ""),
        "ruleset": provenance.get("crypto_ruleset_version", ""),
        "verdict": verdict,
        "verdict_label": en(f"verdict.{verdict}") if verdict else en("result.no_readiness"),
        "verdict_body": en(f"verdict.{verdict}.body") if verdict else "",
        "earliest": (readiness or {}).get("earliest_year"),
        "overdue": len((readiness or {}).get("overdue", [])),
        "complete": (readiness or {}).get("complete", True),
        "source_unread": (readiness or {}).get("source_unread", 0),
        "truncation": meta.get("truncation"),
        "checked": (readiness or {}).get("checked", ""),
        "tally": tally,
        "tally_labels": {s: en(f"st.{s}") for s in STATUSES},
        "sites": sites,
        "implements": implements,
        "other_actionable": dict(other_actionable),
        "actions": actions,
        "findings": rows[:FINDING_ROWS],
        "findings_total": len(rows),
        "patches": patches,
        "guides": guides,
        "refusals": refusals,
        "actionable_total": len(rows) + sum(other_actionable.values()),
        "deadlines": deadlines,
        "deadlines_clear": clear,
        "files_scanned": meta.get("files_scanned", 0),
        "shipped_files": coverage.get("source_files", 0),
        "unparseable": coverage.get("files_unparseable", 0),
        "score_status": score.get("status", ""),
        "agility_score": score.get("agility_score"),
    }
    data["L"] = labels(data)
    return data


def _sentences(*parts: str) -> str:
    return " ".join(p for p in parts if p)


def labels(r: dict[str, Any]) -> dict[str, str]:
    """Every sentence the report prints, in English from site.json, already filled in."""
    static = [
        "title",
        "header",
        "page",
        "recorded",
        "fact_repo",
        "fact_commit",
        "fact_date",
        "fact_verdict",
        "s1",
        "s2",
        "s3",
        "s4",
        "s5",
        "bar_label",
        "actions",
        "col_action",
        "col_when",
        "col_sites",
        "col_where",
        "col_call",
        "col_algorithm",
        "col_status",
        "col_entry",
        "col_reason",
        "col_framework",
        "col_rule",
        "col_year",
        "partial_title",
        "findings_none",
        "changes_lede",
        "patches",
        "guides",
        "refusals",
        "deadlines_none",
        "m_files",
        "m_how",
        "m_how_value",
        "m_readiness",
        "m_readiness_value",
        "m_score",
        "m_versions",
        "scope",
        "footer",
    ]
    out = {key: en(f"doc.{key}") for key in static}
    extra = sum(r["other_actionable"].values())
    shown = len(r["findings"])
    guided = sum(g["count"] for g in r["guides"])
    out.update(
        {
            "html_title": en("doc.html_title", repo=r["repo"]),
            "verdict_line": _sentences(
                r["verdict_body"],
                en("doc.earliest", year=r["earliest"]) if r["earliest"] else "",
                en("doc.overdue", n=r["overdue"]) if r["overdue"] else "",
            ),
            "implements": en("doc.implements", algorithms=", ".join(r["implements"])),
            "implements_body": en("doc.implements_body"),
            "partial": en("doc.partial", n=r["source_unread"]),
            "truncation": (
                en(
                    "doc.truncation",
                    observed=r["truncation"].get("observed", ""),
                    limit=r["truncation"].get("limit", ""),
                    unit=str(r["truncation"].get("reason", ""))
                    .removeprefix("max_")
                    .replace("_", " "),
                )
                if r["truncation"]
                else ""
            ),
            "counted": en("doc.counted", n=r["sites"]),
            "findings_note": _sentences(
                en("doc.findings_note", n=r["findings_total"]),
                en("doc.findings_other", n=extra) if extra else "",
                en("doc.findings_first", n=shown) if r["findings_total"] > shown else "",
            ),
            "changes_counts": en(
                "doc.changes_counts",
                patches=len(r["patches"]),
                sites=guided,
                guides=len(r["guides"]),
                refused=len(r["refusals"]),
            ),
            "deadlines_note": en(
                "doc.deadlines_note", clear=r["deadlines_clear"], checked=r["checked"]
            ),
            "m_files_value": "; ".join(
                p
                for p in (
                    en("doc.m_files_value", n=r["files_scanned"], shipped=r["shipped_files"]),
                    en("doc.m_unparseable", n=r["unparseable"]) if r["unparseable"] else "",
                )
                if p
            ),
            "m_score_value": (
                en("doc.m_score_value", score=f"{r['agility_score']:.1f}")
                if r["score_status"] == "scored" and r["agility_score"] is not None
                else en("doc.m_score_none", status=str(r["score_status"]).replace("_", " "))
            ),
            "m_versions_value": en(
                "doc.m_versions_value", analyzer=r["analyzer"], ruleset=r["ruleset"]
            ),
        }
    )
    return out


def sources_line(sources: list[dict[str, str]]) -> str:
    return en("doc.sources", list="; ".join(s["title"] for s in sources))


def sites_line(sites: list[str], count: int, limit: int = 12) -> str:
    text = " · ".join(sites[:limit])
    return text + (" · " + en("doc.more", n=count - limit) if count > limit else "")
