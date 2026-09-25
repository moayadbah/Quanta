"""The readiness report as a PDF: real text (not a screenshot), embedded fonts, page
headers and numbers, and page breaks that never split a table row.

Pure Python (fpdf2), so it renders inside a serverless function. It reads the same data as
``report.html`` (``core/report_data.py``), so the two documents cannot disagree.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from fpdf import FPDF, XPos, YPos
from fpdf.fonts import FontFace
from fpdf.util import Padding

FONTS = Path(__file__).resolve().parents[1] / "web" / "static" / "brand" / "fonts"
LOGO = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">'
    '<path d="M45.6 46.6A22 22 0 1 1 51.9 31" stroke="#111111" stroke-width="10"/>'
    '<path d="M31 31h13l16 25H47z" fill="#111111"/></svg>'
)
INK = (17, 17, 17)
MUTED = (95, 99, 104)
LINE = (230, 230, 230)
SOFT = (246, 246, 246)
COLOURS = {
    "vulnerable": (201, 48, 44),
    "at_risk": (201, 48, 44),
    "weak": (183, 121, 31),
    "review": (183, 121, 31),
    "in_transition": (183, 121, 31),
    "pq": (47, 125, 74),
    "ready": (47, 125, 74),
    "safe": (154, 160, 166),
    "no_crypto": (154, 160, 166),
    "no_source": (154, 160, 166),
}


def _clean(text: Any) -> str:
    return str(text).replace("\t", "    ").replace("\r", "")


class ReportPDF(FPDF):
    def __init__(self, repo: str, labels: dict[str, str]) -> None:
        super().__init__(format="A4", unit="mm")
        self.repo = repo
        self.labels = labels
        self.set_margins(16, 20, 16)
        self.set_auto_page_break(True, margin=18)
        self.add_font("Inter", "", str(FONTS / "inter-400.ttf"))
        self.add_font("Inter", "B", str(FONTS / "inter-600.ttf"))
        self.add_font("Mono", "", str(FONTS / "geist-mono-400.ttf"))
        self.set_fallback_fonts(["Mono"])
        self.set_title(labels["html_title"])
        self.set_author("Quanta")
        self.set_creator("Quanta")

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_y(9)
        self.set_font("Inter", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 5, self.labels["header"])
        self.set_x(self.l_margin)
        self.cell(0, 5, _clean(self.repo), align="R")
        self.set_draw_color(*LINE)
        self.line(self.l_margin, 15, self.w - self.r_margin, 15)
        self.set_y(20)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Inter", "", 8)
        self.set_text_color(*MUTED)
        page = self.labels["page"].replace("{page}", str(self.page_no())).replace("{pages}", "{nb}")
        self.cell(0, 5, page, align="R")

    # Building blocks -----------------------------------------------------------------------
    def heading(self, text: str) -> None:
        if self.get_y() > self.h - 50:
            self.add_page()
        self.ln(5)
        self.set_draw_color(*LINE)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)
        self.set_font("Inter", "B", 13)
        self.set_text_color(*INK)
        self.multi_cell(0, 7, _clean(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def subheading(self, text: str) -> None:
        if self.get_y() > self.h - 40:
            self.add_page()
        self.ln(2)
        self.set_font("Inter", "B", 10.5)
        self.set_text_color(*INK)
        self.multi_cell(0, 6, _clean(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def para(self, text: str, size: float = 9.5, colour: tuple[int, int, int] = INK) -> None:
        self.set_font("Inter", "", size)
        self.set_text_color(*colour)
        self.multi_cell(0, size * 0.55, _clean(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def code(self, text: str) -> None:
        self.set_font("Mono", "", 7.6)
        self.set_text_color(*INK)
        self.set_fill_color(*SOFT)
        self.multi_cell(
            0,
            3.8,
            _clean(text).rstrip("\n"),
            fill=True,
            padding=Padding(top=2.5, right=3, bottom=2.5, left=3),
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(1.5)

    def table_of(
        self, header: list[str] | None, rows: list[list[str]], widths: tuple[int, ...]
    ) -> None:
        self.set_font("Inter", "", 8.2)
        self.set_text_color(*INK)
        self.set_draw_color(*LINE)
        self.set_fill_color(255, 255, 255)
        head = FontFace(emphasis="BOLD", color=MUTED, fill_color=(255, 255, 255))
        with self.table(
            col_widths=widths,
            headings_style=head,
            line_height=4.2,
            borders_layout="HORIZONTAL_LINES",
            padding=(1.4, 1.5, 1.4, 0),
            text_align="LEFT",
            first_row_as_headings=header is not None,
            cell_fill_mode="NONE",
        ) as table:
            if header is not None:
                table.row([_clean(h) for h in header])
            for row in rows:
                table.row([_clean(cell) for cell in row])
        self.ln(1)


def render_pdf(r: dict[str, Any]) -> bytes:
    """Render the report dictionary from ``core/report_data.build`` to PDF bytes."""
    L = r["L"]  # noqa: N806 (every sentence, from site.json)
    pdf = ReportPDF(r["repo"], L)
    pdf.alias_nb_pages()
    pdf.add_page()

    # Cover -------------------------------------------------------------------------------------
    pdf.image(io.BytesIO(LOGO.encode()), x=16, y=18, w=7, h=7)
    pdf.set_xy(25, 18.8)
    pdf.set_font("Inter", "B", 11)
    pdf.cell(0, 5, "Quanta")
    pdf.set_xy(16, 32)
    pdf.set_font("Inter", "B", 20)
    pdf.cell(0, 9, L["title"], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)
    facts = [
        (L["fact_repo"], r["repo"]),
        (L["fact_commit"], r["commit"] if r["real_commit"] else L["recorded"]),
        (L["fact_date"], r["date"]),
        (L["fact_verdict"], r["verdict_label"]),
    ]
    width = (pdf.w - 32 - 9) / 4
    top = pdf.get_y()
    for index, (label, value) in enumerate(facts):
        x = 16 + index * (width + 3)
        pdf.set_fill_color(*SOFT)
        pdf.rect(x, top, width, 16, style="F", round_corners=True, corner_radius=2)
        pdf.set_xy(x + 3, top + 2.5)
        pdf.set_font("Inter", "", 7.5)
        pdf.set_text_color(*MUTED)
        pdf.cell(width - 6, 4, label)
        pdf.set_xy(x + 3, top + 7.5)
        pdf.set_font("Inter", "B", 9.5)
        pdf.set_text_color(*INK)
        pdf.cell(width - 6, 5, _clean(value)[:34])
    pdf.set_y(top + 20)

    # 1. Readiness ----------------------------------------------------------------------------
    pdf.heading(L["s1"])
    colour = COLOURS.get(r["verdict"], MUTED)
    pdf.set_fill_color(*colour)
    pdf.ellipse(16, pdf.get_y() + 1.6, 3.4, 3.4, style="F")
    pdf.set_x(22)
    pdf.set_font("Inter", "B", 14)
    pdf.set_text_color(*INK)
    pdf.cell(0, 7, _clean(r["verdict_label"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.para(L["verdict_line"], colour=MUTED)
    if r["implements"]:
        pdf.para(f"{L['implements']} {L['implements_body']}")
    if r["truncation"]:
        pdf.para(f"{L['partial_title']} {L['truncation']}")
    if not r["complete"]:
        pdf.para(f"{L['partial_title']} {L['partial']}")
    if r["sites"]:
        y = pdf.get_y() + 1
        x = 16.0
        total = pdf.w - 32
        for status in ("vulnerable", "weak", "review", "pq", "safe"):
            share = r["tally"][status] / r["sites"]
            if share:
                pdf.set_fill_color(*COLOURS[status])
                pdf.rect(x, y, total * share, 3.2, style="F")
                x += total * share
        pdf.set_y(y + 5.5)
        legend = "   ".join(
            f"{r['tally_labels'][s]}: {r['tally'][s]}"
            for s in ("vulnerable", "weak", "review", "pq", "safe")
        )
        pdf.para(legend, size=8.5)
        pdf.para(L["counted"], size=8.2, colour=MUTED)
    if r["actions"]:
        pdf.subheading(L["actions"])
        pdf.table_of(
            ["#", L["col_action"], L["col_when"], L["col_sites"]],
            [
                [str(a["rank"]), f"{a['title']}\n{a['body']}", a["when"], str(a["sites"])]
                for a in r["actions"]
            ],
            (6, 120, 34, 18),
        )

    # 2. Findings --------------------------------------------------------------------------------
    pdf.heading(L["s2"])
    if r["findings"]:
        pdf.para(L["findings_note"], size=8.2, colour=MUTED)
        pdf.table_of(
            [L["col_where"], L["col_call"], L["col_algorithm"], L["col_status"], L["col_entry"]],
            [
                [f["where"], f["name"], f["algorithm"], f["status_label"], f["entry"]]
                for f in r["findings"]
            ],
            (46, 56, 20, 32, 24),
        )
    else:
        pdf.para(L["findings_none"], colour=MUTED)

    # 3. Changes -----------------------------------------------------------------------------------
    pdf.heading(L["s3"])
    pdf.para(L["changes_lede"], colour=MUTED)
    pdf.para(L["changes_counts"], size=8.2, colour=MUTED)
    if r["patches"]:
        pdf.subheading(L["patches"])
        for patch in r["patches"]:
            pdf.para(patch["where"], size=8, colour=MUTED)
            pdf.code(f"- {patch['before']}\n+ {patch['after']}")
    if r["guides"]:
        pdf.subheading(L["guides"])
    for guide in r["guides"]:
        pdf.subheading(f"{guide['title']}  ·  {guide['sites_label']}")
        pdf.para(f"{guide['body']} {guide['target']}", size=8.6, colour=MUTED)
        pdf.code(guide["example"])
        pdf.para(guide["sites_line"], size=7.6, colour=MUTED)
        pdf.para(guide["sources_line"], size=7.6, colour=MUTED)
    if r["refusals"]:
        pdf.subheading(L["refusals"])
        pdf.table_of(
            [L["col_where"], L["col_reason"]],
            [[x["where"], f"{x['title']}. {x['detail']}"] for x in r["refusals"]],
            (52, 126),
        )

    # 4. Deadlines ---------------------------------------------------------------------------------
    pdf.heading(L["s4"])
    if r["deadlines"]:
        pdf.table_of(
            [L["col_framework"], L["col_rule"], L["col_year"], L["col_sites"], L["col_status"]],
            [
                [
                    d["framework"],
                    f"{d['rule']}\n{d['source']['title']}",
                    str(d["year"]),
                    str(d["sites"]),
                    d["state_label"],
                ]
                for d in r["deadlines"]
            ],
            (28, 98, 14, 14, 24),
        )
        pdf.para(L["deadlines_note"], size=8.2, colour=MUTED)
    else:
        pdf.para(L["deadlines_none"], colour=MUTED)

    # 5. Method ------------------------------------------------------------------------------------
    pdf.heading(L["s5"])
    pdf.table_of(
        None,
        [
            [L["m_files"], L["m_files_value"]],
            [L["m_how"], L["m_how_value"]],
            [L["m_readiness"], L["m_readiness_value"]],
            [L["m_score"], L["m_score_value"]],
            [L["m_versions"], L["m_versions_value"]],
        ],
        (32, 146),
    )
    pdf.para(L["scope"], size=8.2, colour=MUTED)
    return bytes(pdf.output())
