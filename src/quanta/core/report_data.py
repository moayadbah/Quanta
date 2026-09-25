"""One description of a finished analysis, rendered twice: the HTML report and the PDF.

Both documents read the same dictionary, so they cannot disagree, and every word comes from
``content/site.json`` in the reader's language. Order follows what a reader needs: readiness
first, then the findings behind it, the proposed changes, the deadlines, the agility score,
and last the method.

The builder never turns a missing fact into a reassuring one. "Nothing needs action", "no
deadline applies" and "0 shipped files" are only ever stated when the run measured them;
an older engine's run (see ``core/legacy.py``) says plainly what it did not measure and
offers a rescan instead.
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
#: Patches shown with their context; the rest are counted.
PATCH_ROWS = 12
LANGUAGES = ("en", "ar")


@lru_cache(maxsize=1)
def _strings() -> dict[str, dict[str, str]]:
    payload = json.loads(asset_path("content/site.json").read_text(encoding="utf-8"))
    table: dict[str, dict[str, str]] = payload["strings"]
    return table


def tr(key: str, lang: str = "en", **values: Any) -> str:
    """The string for ``key`` in ``lang`` (English if missing), placeholders filled."""
    entry = _strings().get(key, {})
    text = entry.get(lang) or entry.get("en") or key
    for name, value in values.items():
        text = text.replace("{" + name + "}", str(value))
    return text


def en(key: str, **values: Any) -> str:
    return tr(key, "en", **values)


def has(key: str) -> bool:
    return key in _strings()


def _source(source_id: str, lang: str) -> dict[str, str]:
    source = standards()["sources"].get(source_id, {})
    return {
        "id": source_id,
        "title": tr(f"src.{source_id}", lang),
        "publisher": str(source.get("publisher", "")),
        "url": str(source.get("url", "")),
        "status": str(source.get("status", "")),
    }


def _when(stamp: str) -> str:
    """``2026-09-25T07:47:05+00:00`` as ``2026-09-25 07:47 UTC``; empty stays empty."""
    stamp = str(stamp or "")
    if len(stamp) < 16:
        return stamp[:10]
    return f"{stamp[:10]} {stamp[11:16]} UTC"


def build(
    *,
    score: dict[str, Any],
    meta: dict[str, Any],
    readiness: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    fixes: dict[str, Any],
    lang: str = "en",
    assessed: bool | None = None,
    roles_measured: bool | None = None,
    older_engine: str = "",
    run: dict[str, Any] | None = None,
    rescan_url: str = "",
    font_base: str = "",
) -> dict[str, Any]:
    lang = lang if lang in LANGUAGES else "en"

    def T(key: str, **values: Any) -> str:  # noqa: N802 (reads like the frontend's t())
        return tr(key, lang, **values)

    assessed = readiness is not None if assessed is None else assessed and readiness is not None
    if roles_measured is None:
        roles_measured = all(f.get("role") for f in findings) if findings else assessed
    provenance = score.get("provenance", {})
    shipped = [f for f in findings if f.get("role") == "source"]
    other = [f for f in findings if f.get("role") != "source"]

    def status(f: dict[str, Any]) -> str:
        return str((f.get("readiness") or {}).get("status") or "review")

    patched = {(f["path"], c["line"]) for f in fixes.get("files", []) for c in f["changes"]}
    refused = {(s["path"], s["line"]) for s in fixes.get("skipped", [])}
    guided = {(s["path"], s["line"]): g["id"] for g in fixes.get("guides", []) for s in g["sites"]}

    def entry(f: dict[str, Any]) -> str:
        key = (f["file"], f["line"])
        if key in patched:
            return T("report.entry.patch")
        if key in refused:
            return T("report.entry.refused")
        if key in guided:
            return T("report.entry.guide")
        return ""

    rows = [
        {
            "where": f"{f['file']}:{f['line']}",
            "name": str(f.get("name", "")),
            "algorithm": str(f.get("algorithm") or ", ".join(f.get("algorithms") or [])),
            "status": status(f),
            "status_label": T(f"st.{status(f)}"),
            "entry": entry(f),
            "implementation": f.get("form") == "implementation",
        }
        for f in shipped
        if status(f) in ACTIONABLE
    ]
    order = {s: i for i, s in enumerate(STATUSES)}
    rows.sort(key=lambda r: (order[str(r["status"])], str(r["where"])))

    counts = (readiness or {}).get("counts", {}) if assessed else {}
    tally = {s: int(counts.get(s, 0)) for s in STATUSES}
    sites = int(counts.get("sites", 0))
    verdict = str((readiness or {}).get("verdict", "")) if assessed else "not_assessed"
    implements = sorted(
        {str(f.get("algorithm")) for f in shipped if f.get("form") == "implementation"}
    )
    other_actionable = Counter(status(f) for f in other if status(f) in ACTIONABLE)

    actions = []
    for rank, action in enumerate((readiness or {}).get("actions", []) if assessed else [], 1):
        by = action.get("by")
        in_force = bool(action.get("in_force"))
        overdue = in_force or bool(by and readiness and by <= readiness.get("reference_year", 0))
        sources = [_source(s, lang) for s in action.get("sources", [])]
        actions.append(
            {
                "rank": rank,
                "title": T(f"action.{action['id']}.title"),
                "body": T(f"action.{action['id']}.body"),
                "when": (
                    T("ready.in_force")
                    if in_force
                    else T("ready.overdue_since", year=by)
                    if overdue
                    else T("ready.by", year=by)
                    if by
                    else T("ready.no_date")
                ),
                "overdue": overdue,
                "sites": action.get("sites", 0),
                "sites_label": T("ready.sites", n=action.get("sites", 0)),
                "sources": sources,
                "sources_line": T("doc.sources", list="; ".join(s["title"] for s in sources)),
            }
        )

    milestones = [
        m
        for m in ((readiness or {}).get("milestones", []) if assessed else [])
        if m.get("state") in {"overdue", "due"}
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
            "framework": T(f"fw.{m['framework']}"),
            "rule": T(f"ms.{m['id']}"),
            "year": (
                T("readiness.after", year=m["year"])
                if m.get("in_force") and m.get("year")
                else T("readiness.in_force")
                if m.get("in_force")
                else m.get("year") or T("readiness.any_date")
            ),
            "sites": m.get("sites", 0),
            "state": m["state"],
            "state_label": T(f"ms.state.{m['state']}"),
            "source": _source(m["source"], lang),
        }
        for m in milestones
    ]
    clear = sum(
        1
        for m in ((readiness or {}).get("milestones", []) if assessed else [])
        if m.get("state") == "clear"
    )

    catalogue = migrations()
    patches = []
    for f in fixes.get("files", []):
        for c in f["changes"]:
            before = c.get("line_before") or ""
            after = c.get("line_after") or ""
            if not before or not after:
                # A change without its full line is from an engine that no longer applies;
                # reevaluate() replaces those, so one here is never shown as a proposal.
                continue
            start = int(c.get("context_start") or c["line"])
            lines = [
                {"no": start + i, "kind": " ", "text": text}
                for i, text in enumerate(c.get("context_before") or [])
            ]
            lines.append({"no": c["line"], "kind": "-", "text": before})
            lines.append({"no": c["line"], "kind": "+", "text": after})
            lines += [
                {"no": c["line"] + 1 + i, "kind": " ", "text": text}
                for i, text in enumerate(c.get("context_after") or [])
            ]
            patches.append(
                {
                    "path": f["path"],
                    "line": c["line"],
                    "where": f"{f['path']}:{c['line']}",
                    "lines": lines,
                    "rule": T(f"rule.{c.get('rule', '')}") if has(f"rule.{c.get('rule')}") else "",
                }
            )
    patches_total = len(patches)
    guides = []
    for g in fixes.get("guides", []):
        item = catalogue.get(g["id"], {})
        sources = [_source(s, lang) for s in item.get("sources", [])]
        where = [f"{s['path']}:{s['line']}" for s in g["sites"]]
        guides.append(
            {
                "id": g["id"],
                "title": T(f"guide.{g['id']}.title")
                if has(f"guide.{g['id']}.title")
                else T("guide.other.title"),
                "body": T(f"guide.{g['id']}.body")
                if has(f"guide.{g['id']}.body")
                else T("guide.other.body"),
                "to": T(f"guide.{g['id']}.to")
                if has(f"guide.{g['id']}.to")
                else item.get("to", ""),
                "example": item.get("example", ""),
                "count": len(g["sites"]),
                "sites": where,
                "sites_line": " · ".join(where[:12])
                + (" · " + T("doc.more", n=len(where) - 12) if len(where) > 12 else ""),
                "target": T(
                    "doc.target",
                    to=T(f"guide.{g['id']}.to")
                    if has(f"guide.{g['id']}.to")
                    else item.get("to", ""),
                ),
                "sites_label": T("ready.sites", n=len(g["sites"])),
                "sources": sources,
                "sources_line": T("doc.sources", list="; ".join(s["title"] for s in sources)),
            }
        )
    refusals = [
        {
            "where": f"{s['path']}:{s['line']}",
            "title": T(f"refusal.{s['code']}.title")
            if has(f"refusal.{s['code']}.title")
            else T("refusal.other.title"),
            "detail": T(f"refusal.{s['code']}.body")
            if has(f"refusal.{s['code']}.body")
            else T("refusal.other.body"),
        }
        for s in fixes.get("skipped", [])
    ]

    coverage = score.get("coverage", {})
    shipped_files = coverage.get("source_files") if "source_files" in coverage else None
    agility = _agility(score, T)
    commit = str(provenance.get("commit_sha", ""))
    data: dict[str, Any] = {
        "lang": lang,
        "dir": "rtl" if lang == "ar" else "ltr",
        "repo": provenance.get("repo", ""),
        "commit": commit[:12],
        "real_commit": bool(commit) and not set(commit) <= {"0"},
        "date": str(meta.get("finished_at", ""))[:10],
        "analyzer": provenance.get("analyzer_version", ""),
        "ruleset": provenance.get("crypto_ruleset_version", ""),
        "assessed": assessed,
        "roles_measured": roles_measured,
        "older_engine": older_engine,
        "rescan_url": rescan_url,
        "verdict": verdict,
        "verdict_label": T(f"verdict.{verdict}"),
        "verdict_body": T(f"verdict.{verdict}.body"),
        "earliest": (readiness or {}).get("earliest_year") if assessed else None,
        "overdue": len((readiness or {}).get("overdue", [])) if assessed else 0,
        "complete": (readiness or {}).get("complete", True),
        "source_unread": (readiness or {}).get("source_unread", 0),
        "truncation": meta.get("truncation"),
        "checked": (readiness or {}).get("checked", ""),
        "tally": tally,
        "tally_labels": {s: T(f"st.{s}") for s in STATUSES},
        "sites": sites,
        "implements": implements,
        "other_actionable": dict(other_actionable),
        "actions": actions,
        "findings": rows[:FINDING_ROWS],
        "findings_total": len(rows),
        "findings_all": len(findings),
        "patches": patches[:PATCH_ROWS],
        "patches_total": patches_total,
        "guides": guides,
        "refusals": refusals,
        "actionable_total": len(rows) + sum(other_actionable.values()),
        "deadlines": deadlines,
        "deadlines_clear": clear,
        "files_scanned": meta.get("files_scanned", coverage.get("files_scanned", 0)),
        "shipped_files": shipped_files,
        "unparseable": coverage.get("files_unparseable", 0),
        "score_status": score.get("status") or "",
        "agility_score": score.get("agility_score"),
        "agility": agility,
        "run": {"avatar_data": "", "login": "", **(run or {})},
        "font_base": font_base,
    }
    data["L"] = labels(data, T)
    return data


def _agility(score: dict[str, Any], T: Any) -> dict[str, Any]:  # noqa: N803
    """The agility score as a short secondary section: each factor, how much it costs."""
    lost = {d.get("factor"): d for d in score.get("deductions", []) if d.get("factor")}
    factors = []
    for key, factor in (score.get("factors") or {}).items():
        if not isinstance(factor, dict) or not has(f"factor.{key}.name"):
            continue
        inputs = factor.get("inputs") or {}
        deduction = lost.get(key) or {}
        factors.append(
            {
                "key": key,
                "name": T(f"factor.{key}.name"),
                "why": T(f"factor.{key}.why", **dict(inputs)),
                "value": float(factor.get("normalised") or 0),
                "weight": float(factor.get("weight") or 0),
                "lost": float(deduction.get("points") or 0),
                "citations": list(deduction.get("citations") or [])[:4],
            }
        )
    return {"score": score.get("agility_score"), "factors": factors}


def _sentences(*parts: str) -> str:
    return " ".join(p for p in parts if p)


def labels(r: dict[str, Any], T: Any) -> dict[str, str]:  # noqa: N803
    """Every sentence the report prints, already filled in, in the report's language."""
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
        "s6",
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
        "changes_lede",
        "patches",
        "guides",
        "refusals",
        "m_files",
        "m_how",
        "m_how_value",
        "m_readiness",
        "m_readiness_value",
        "m_score",
        "m_versions",
        "scope",
        "footer",
        "summary_title",
        "k_sites",
        "k_vulnerable",
        "k_weak",
        "k_review",
        "k_earliest",
        "k_entries",
        "fact_scanned",
        "legacy_title",
        "rescan",
        "agility_lede",
        "not_measured",
        "implementation",
        "not_assessed_body",
        "cover_kicker",
        "contents",
        "k_calls",
    ]
    out = {key: T(f"doc.{key}") for key in static}
    rtl = r["lang"] == "ar"

    def iso(value: Any) -> str:
        """Dates, versions and names keep their left-to-right order inside Arabic."""
        return f"⁦{value}⁩" if rtl and value else str(value)

    extra = sum(r["other_actionable"].values())
    shown = len(r["findings"])
    guided = sum(g["count"] for g in r["guides"])
    run = r["run"]
    if run.get("kind") == "sample":
        who = T("doc.run_sample", when=iso(_when(run.get("at", ""))))
    elif run.get("kind") == "user":
        name = run.get("name") or run.get("login", "")
        who = T(
            "doc.run_user",
            name=name,
            login=iso("@" + str(run.get("login", ""))),
            when=iso(_when(run.get("at", ""))),
        )
    else:
        who = T("doc.run_local", when=iso(_when(run.get("at", "") or r["date"])))
    shipped = r["shipped_files"]
    if not r["assessed"]:
        findings_note = _sentences(
            T("doc.legacy_findings", n=r["findings_total"]),
            T("doc.findings_first", n=shown) if r["findings_total"] > shown else "",
        )
        findings_none = T("doc.legacy_findings_none")
        deadlines_none = T("doc.legacy_deadlines")
    else:
        findings_note = _sentences(
            T("doc.findings_note", n=r["findings_total"]),
            T("doc.findings_other", n=extra) if extra else "",
            T("doc.findings_first", n=shown) if r["findings_total"] > shown else "",
        )
        actionable = sum(r["tally"][s] for s in ACTIONABLE)
        # A clean line only when the assessment measured zero; otherwise the list is missing.
        findings_none = T("doc.findings_none") if not actionable else T("doc.findings_unavailable")
        deadlines_none = T("doc.deadlines_none")
    status = str(r["score_status"])
    status_label = T(f"status.score.{status}") if has(f"status.score.{status}") else ""
    out.update(
        {
            "html_title": T("doc.html_title", repo=r["repo"]),
            "verdict_line": _sentences(
                r["verdict_body"],
                T("doc.earliest", year=r["earliest"]) if r["earliest"] else "",
                T("doc.overdue", n=r["overdue"]) if r["overdue"] else "",
            ),
            "who": who,
            "local_commit": T("doc.recorded")
            if run.get("kind") == "sample"
            else T("doc.local_commit"),
            "legacy": T("doc.legacy", version=r["older_engine"] or r["analyzer"] or "?"),
            "outdated": T("doc.outdated", version=r["older_engine"]) if r["older_engine"] else "",
            "implements": T("doc.implements", algorithms=", ".join(r["implements"])),
            "implements_body": T("doc.implements_body"),
            "partial": T("doc.partial", n=r["source_unread"]) if not r["complete"] else "",
            "truncation": (
                T(
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
            "counted": T("doc.counted", n=r["sites"]) if r["sites"] else "",
            "findings_note": findings_note,
            # Only ever computed when it is the sentence the report prints.
            "findings_none": "" if r["findings"] else findings_none,
            "deadlines_none": "" if r["deadlines"] else deadlines_none,
            "changes_counts": T(
                "doc.changes_counts",
                patches=r["patches_total"],
                sites=guided,
                guides=len(r["guides"]),
                refused=len(r["refusals"]),
            ),
            "patches_more": (
                T("doc.patches_more", n=r["patches_total"] - len(r["patches"]))
                if r["patches_total"] > len(r["patches"])
                else ""
            ),
            "deadlines_note": T(
                "doc.deadlines_note", clear=r["deadlines_clear"], checked=r["checked"]
            ),
            "m_files_value": "; ".join(
                p
                for p in (
                    T("doc.m_files_value", n=r["files_scanned"], shipped=shipped)
                    if shipped is not None
                    else T("doc.m_files_unmeasured", n=r["files_scanned"]),
                    T("doc.m_unparseable", n=r["unparseable"]) if r["unparseable"] else "",
                )
                if p
            ),
            "m_score_value": (
                T("doc.m_score_value", score=f"{r['agility_score']:.1f}")
                if status == "scored" and r["agility_score"] is not None
                else T("doc.m_score_none", status=status_label)
                if status_label
                else T("doc.m_score_none_plain")
            ),
            "m_versions_value": T(
                "doc.m_versions_value", analyzer=iso(r["analyzer"]), ruleset=iso(r["ruleset"])
            ),
            "k_entries_value": T(
                "doc.k_entries_value",
                patches=r["patches_total"],
                guided=guided,
                refused=len(r["refusals"]),
            ),
        }
    )
    return out
