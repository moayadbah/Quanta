"""The readiness report as a PDF a security firm could hand a client.

Real text (not a screenshot), embedded fonts, a cover page with the verdict in colour and the
key numbers, then the sections. Pure Python (fpdf2, with HarfBuzz shaping for Arabic), so
it renders inside a serverless function. It reads the same dictionary as the HTML report
(``core/report_data.py``), so the two documents cannot disagree.

Nothing overflows: every box is sized from the measured lines of its own text, long words
(paths, repository names) break by character, and the running header truncates with an
ellipsis. Arabic is laid out right to left, mirrored, with code and paths kept left to right.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from fpdf import FPDF, XPos, YPos
from fpdf.enums import MethodReturnValue, WrapMode
from fpdf.fonts import FontFace
from fpdf.util import Padding

FONTS = Path(__file__).resolve().parents[1] / "web" / "static" / "brand" / "fonts"
INK = (10, 10, 10)
MUTED = (95, 99, 104)
SUBTLE = (138, 143, 152)
LINE = (232, 232, 232)
SOFT = (245, 245, 245)
BLUE = (7, 97, 209)
WHITE = (255, 255, 255)
RED = (201, 48, 44)
AMBER = (183, 121, 31)
AMBER_INK = (138, 90, 18)
AMBER_BG = (253, 243, 225)
GREEN = (47, 125, 74)
GREY = (107, 114, 128)
DEL_BG = (253, 236, 234)
ADD_BG = (232, 244, 236)
BAND = {
    "at_risk": RED,
    "in_transition": AMBER,
    "not_assessed": AMBER,
    "ready": GREEN,
    "no_crypto": GREY,
    "no_source": GREY,
}
STATUS = {"vulnerable": RED, "weak": AMBER, "review": AMBER, "pq": GREEN, "safe": (196, 199, 204)}
PAPER = {"a4": "A4", "letter": "Letter"}
#: Left-to-right isolate: paths and code keep their order inside Arabic text.
LRI, PDI = "⁦", "⁩"


def _clean(text: Any) -> str:
    return str(text).replace("\t", "    ").replace("\r", "")


class ReportPDF(FPDF):
    def __init__(self, r: dict[str, Any], paper: str = "a4", total: int = 0) -> None:
        super().__init__(format=PAPER.get(paper.lower(), "A4"), unit="mm")
        self.r = r
        #: The page count from a first pass: fpdf's {nb} alias cannot reach shaped text.
        self.total = total
        self.L = r["L"]
        self.rtl = r.get("dir") == "rtl"
        self.set_margins(18, 20, 18)
        self.set_auto_page_break(True, margin=18)
        self.add_font("Mono", "", str(FONTS / "geist-mono-400.ttf"))
        if self.rtl:
            self.add_font("Sans", "", str(FONTS / "readex-pro-400.ttf"))
            self.add_font("Sans", "B", str(FONTS / "readex-pro-600.ttf"))
        else:
            self.add_font("Sans", "", str(FONTS / "inter-400.ttf"))
            self.add_font("Sans", "B", str(FONTS / "inter-600.ttf"))
        self.set_fallback_fonts(["Mono"])
        self.shape()
        self.set_title(self.L["html_title"])
        self.set_author("Quanta")
        self.set_creator("Quanta")
        self.set_lang(r.get("lang", "en"))

    def shape(self, ltr: bool = False) -> None:
        """Arabic is shaped right to left; code and paths inside it left to right."""
        if not self.rtl:
            return
        if ltr:
            self.set_text_shaping(use_shaping_engine=True, direction="ltr")
        else:
            self.set_text_shaping(
                use_shaping_engine=True, direction="rtl", script="arab", language="ara"
            )

    # Geometry ------------------------------------------------------------------------------
    @property
    def width(self) -> float:
        return self.w - self.l_margin - self.r_margin

    def at(self, offset: float, width: float) -> float:
        """The x of a box ``offset`` from the reading start, mirrored in Arabic."""
        if self.rtl:
            return self.w - self.r_margin - offset - width
        return self.l_margin + offset

    @property
    def start(self) -> str:
        return "R" if self.rtl else "L"

    @property
    def end(self) -> str:
        return "L" if self.rtl else "R"

    def ltr(self, text: Any) -> str:
        """Code, paths and hashes read left to right, also inside Arabic."""
        return f"{LRI}{_clean(text)}{PDI}" if self.rtl else _clean(text)

    def space(self, needed: float) -> None:
        if self.get_y() + needed > self.h - self.b_margin:
            self.add_page()

    def lines(
        self, width: float, text: str, size: float, style: str = "", font: str = "Sans"
    ) -> int:
        self.set_font(font, style, size)
        wrap = WrapMode.CHAR if font == "Mono" else WrapMode.WORD
        found = self.multi_cell(
            width, 1, _clean(text), dry_run=True, output=MethodReturnValue.LINES, wrapmode=wrap
        )
        return max(1, len(found)) if isinstance(found, list) else 1

    # Running header and footer ------------------------------------------------------------
    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_y(10)
        self.set_font("Sans", "", 7.5)
        self.set_text_color(*SUBTLE)
        repo = _clean(self.r["repo"])
        room = self.width * 0.5
        while len(repo) > 1 and self.get_string_width(repo) > room:
            repo = repo[:-2] + "…"
        self.set_x(self.l_margin)
        self.cell(self.width, 4, self.L["header"], align=self.start)
        self.set_x(self.l_margin)
        self.cell(self.width, 4, self.ltr(repo), align=self.end)
        self.set_draw_color(*LINE)
        self.set_line_width(0.2)
        self.line(self.l_margin, 15.5, self.w - self.r_margin, 15.5)
        self.set_y(22)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Sans", "", 7.5)
        self.set_text_color(*SUBTLE)
        page = self.L["page"].replace("{page}", str(self.page_no()))
        page = page.replace("{pages}", str(self.total or self.page_no()))
        self.set_x(self.l_margin)
        self.cell(self.width, 4, page, align=self.end)
        self.set_x(self.l_margin)
        self.cell(self.width, 4, "Quanta", align=self.start)

    # Building blocks -----------------------------------------------------------------------
    def section(self, number: int, title: str) -> None:
        self.space(36)
        if self.get_y() > self.t_margin + 4:
            self.ln(8)
        y = self.get_y()
        self.set_font("Mono", "", 9)
        self.set_text_color(*BLUE)
        self.set_xy(self.at(0, 8), y + 1.4)
        self.cell(8, 6, str(number), align=self.start)
        self.set_font("Sans", "B", 14)
        self.set_text_color(*INK)
        self.set_xy(self.at(8, self.width - 8), y)
        self.multi_cell(
            self.width - 8, 7.5, title, align=self.start, new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        self.ln(2.5)

    def subheading(self, text: str, keep: float = 24) -> None:
        """A heading that never ends a page: ``keep`` is the room its first item needs."""
        self.space(keep)
        self.ln(2)
        self.set_font("Sans", "B", 10.5)
        self.set_text_color(*INK)
        self.set_x(self.l_margin)
        self.multi_cell(self.width, 6, text, align=self.start, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def para(
        self,
        text: str,
        size: float = 9.5,
        colour: tuple[int, int, int] = INK,
        style: str = "",
    ) -> None:
        if not text:
            return
        self.set_font("Sans", style, size)
        self.set_text_color(*colour)
        self.set_x(self.l_margin)
        self.multi_cell(
            self.width,
            size * 0.55,
            _clean(text),
            align=self.start,
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(1.2)

    def note(self, text: str, tint: tuple[int, int, int] = SOFT) -> None:
        height = self.lines(self.width - 8, text, 9) * 5 + 6
        self.space(height + 2)
        y = self.get_y()
        self.set_fill_color(*tint)
        self.rect(
            self.l_margin, y, self.width, height, style="F", round_corners=True, corner_radius=2
        )
        self.set_xy(self.l_margin + 4, y + 3)
        self.set_font("Sans", "", 9)
        self.set_text_color(*INK)
        self.multi_cell(
            self.width - 8, 5, text, align=self.start, new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        self.set_y(y + height + 3)

    def code(self, text: str, size: float = 7.4) -> None:
        self.shape(ltr=True)
        self.set_font("Mono", "", size)
        self.set_text_color(*INK)
        self.set_fill_color(*SOFT)
        self.set_x(self.l_margin)
        self.multi_cell(
            self.width,
            size * 0.5,
            _clean(text).rstrip("\n"),
            fill=True,
            align="L",
            padding=Padding(top=2.5, right=3, bottom=2.5, left=3),
            wrapmode=WrapMode.CHAR,
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.shape()
        self.ln(2)

    def table_of(
        self,
        header: list[str] | None,
        rows: list[list[Any]],
        widths: tuple[float, ...],
        styles: list[list[FontFace | None]] | None = None,
        mono: set[int] | None = None,
    ) -> None:
        mono = set(mono or ())
        if self.rtl:
            header = list(reversed(header)) if header else None
            rows = [list(reversed(row)) for row in rows]
            styles = [list(reversed(s)) for s in styles] if styles else None
            widths = tuple(reversed(widths))
            mono = {len(widths) - 1 - i for i in mono}
        total = sum(widths)
        scaled = tuple(w * self.width / total for w in widths)
        self.set_fill_color(*WHITE)
        self.set_font("Sans", "", 8.4)
        self.set_text_color(*INK)
        self.set_draw_color(*LINE)
        self.set_line_width(0.2)
        head = FontFace(emphasis="BOLD", color=MUTED, fill_color=WHITE, size_pt=7.8)
        with self.table(
            col_widths=scaled,
            width=self.width,
            text_align="RIGHT" if self.rtl else "LEFT",
            line_height=4.6,
            padding=(1.6, 1.4, 1.6, 1.4),
            borders_layout="HORIZONTAL_LINES",
            first_row_as_headings=header is not None,
            headings_style=head,
            cell_fill_mode="NONE",
            wrapmode=WrapMode.WORD,
        ) as table:
            if header is not None:
                table.row(header)
            for index, row in enumerate(rows):
                cells = table.row()
                for column, value in enumerate(row):
                    style = styles[index][column] if styles else None
                    if column in mono:
                        face = FontFace(
                            family="Mono", size_pt=7.6, color=style.color if style else None
                        )
                        cells.cell(self.ltr(value), style=face)
                    else:
                        cells.cell(_clean(value), style=style)
        self.ln(2)


def _band(pdf: ReportPDF, colour: tuple[int, int, int], label: str, body: str) -> None:
    inner = pdf.width - 14
    height = 6 + pdf.lines(inner, label, 19, "B") * 9 + 2 + pdf.lines(inner, body, 9.5) * 5.2 + 6
    pdf.space(height + 4)
    y = pdf.get_y()
    pdf.set_fill_color(*colour)
    pdf.rect(pdf.l_margin, y, pdf.width, height, style="F", round_corners=True, corner_radius=3)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Sans", "B", 19)
    pdf.set_xy(pdf.l_margin + 7, y + 6)
    pdf.multi_cell(inner, 9, label, align=pdf.start, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)
    pdf.set_font("Sans", "", 9.5)
    pdf.set_x(pdf.l_margin + 7)
    pdf.multi_cell(inner, 5.2, body, align=pdf.start, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_y(y + height + 5)


def _tiles(pdf: ReportPDF, tiles: list[tuple[str, str, tuple[int, int, int] | None, bool]]) -> None:
    gap = 3
    count = len(tiles)
    width = (pdf.width - gap * (count - 1)) / count
    inner = width - 7
    heights = []
    for value, key, _colour, text in tiles:
        value_h = pdf.lines(inner, value, 9 if text else 18, "B") * (4.6 if text else 8.5)
        key_h = pdf.lines(inner, key, 7.6) * 3.8
        heights.append(value_h + 1.5 + key_h)
    height = max(heights) + 8
    pdf.space(height + 4)
    y = pdf.get_y()
    for index, (value, key, colour, text) in enumerate(tiles):
        x = pdf.at(index * (width + gap), width)
        pdf.set_fill_color(*SOFT)
        pdf.rect(x, y, width, height, style="F", round_corners=True, corner_radius=2.5)
        pdf.set_xy(x + 3.5, y + 4)
        pdf.set_font("Sans", "B", 9 if text else 18)
        pdf.set_text_color(*(colour or INK))
        pdf.multi_cell(
            inner, 4.6 if text else 8.5, value, align=pdf.start, new_x=XPos.LEFT, new_y=YPos.NEXT
        )
        pdf.set_xy(x + 3.5, pdf.get_y() + 1.5)
        pdf.set_font("Sans", "", 7.6)
        pdf.set_text_color(*MUTED)
        pdf.multi_cell(inner, 3.8, key, align=pdf.start, new_x=XPos.LEFT, new_y=YPos.NEXT)
    pdf.set_y(y + height + 7)


def _strip(pdf: ReportPDF, label: str, value: str) -> None:
    """One line under the tiles: the proposed changes, counted."""
    pdf.set_font("Sans", "B", 9.5)
    label_w = min(pdf.width / 2, pdf.get_string_width(label) + 6)
    height = max(pdf.lines(pdf.width - label_w - 10, value, 9.5), 1) * 5 + 6
    y = pdf.get_y() - 3
    pdf.set_fill_color(*SOFT)
    pdf.rect(pdf.l_margin, y, pdf.width, height, style="F", round_corners=True, corner_radius=2.5)
    pdf.set_text_color(*MUTED)
    pdf.set_font("Sans", "", 8.4)
    pdf.set_xy(pdf.at(3.5, label_w), y + 3.3)
    pdf.cell(label_w, 5, label, align=pdf.start)
    pdf.set_text_color(*INK)
    pdf.set_font("Sans", "B", 9.5)
    pdf.set_xy(pdf.at(label_w + 5, pdf.width - label_w - 10), y + 3)
    pdf.multi_cell(
        pdf.width - label_w - 10, 5, value, align=pdf.start, new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    pdf.set_y(y + height + 7)


def _logo(pdf: ReportPDF, x: float, y: float, size: float) -> None:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">'
        '<path d="M45.6 46.6A22 22 0 1 1 51.9 31" stroke="#0a0a0a" stroke-width="10"/>'
        '<path d="M31 31h13l16 25H47z" fill="#0a0a0a"/></svg>'
    )
    pdf.image(io.BytesIO(svg.encode()), x=x, y=y, w=size, h=size)


def _who(pdf: ReportPDF) -> None:
    run = pdf.r["run"]
    y = pdf.get_y()
    offset = 0.0
    avatar = run.get("avatar_bytes")
    if avatar:
        try:
            with pdf.round_clip(x=pdf.at(0, 7), y=y, r=7):
                pdf.image(io.BytesIO(avatar), x=pdf.at(0, 7), y=y, w=7, h=7)
            offset = 9.5
        except Exception:
            offset = 0.0
    if not offset and run.get("login"):
        pdf.set_fill_color(*INK)
        pdf.ellipse(pdf.at(0, 7), y, 7, 7, style="F")
        pdf.set_font("Sans", "B", 8)
        pdf.set_text_color(*WHITE)
        pdf.set_xy(pdf.at(0, 7), y + 1)
        pdf.cell(7, 5, run["login"][:1].upper(), align="C")
        offset = 9.5
    pdf.set_font("Sans", "", 9.5)
    pdf.set_text_color(*INK)
    pdf.set_xy(pdf.at(offset, pdf.width - offset), y + 1)
    pdf.multi_cell(
        pdf.width - offset, 5.2, pdf.L["who"], align=pdf.start, new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    pdf.set_y(max(pdf.get_y(), y + 8))


def _cover(pdf: ReportPDF) -> None:
    r, L = pdf.r, pdf.L  # noqa: N806
    top = 18
    _logo(pdf, pdf.at(0, 7), top, 7)
    pdf.set_font("Sans", "B", 12)
    pdf.set_text_color(*INK)
    pdf.set_xy(pdf.at(9, 40), top + 0.6)
    pdf.cell(40, 6, "Quanta", align=pdf.start)
    pdf.set_font("Sans", "", 8.5)
    pdf.set_text_color(*MUTED)
    pdf.set_xy(pdf.l_margin, top + 0.8)
    pdf.cell(pdf.width, 6, L["title"], align=pdf.end)
    pdf.set_draw_color(*LINE)
    pdf.set_line_width(0.2)
    pdf.line(pdf.l_margin, top + 11, pdf.w - pdf.r_margin, top + 11)

    # Repository, commit and who ran it.
    pdf.set_y(top + 22)
    pdf.para(L["fact_repo"], size=9, colour=MUTED)
    pdf.shape(ltr=True)
    pdf.set_font("Mono", "", 20)
    pdf.set_text_color(*INK)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(
        pdf.width,
        9.5,
        _clean(r["repo"]),
        align=pdf.start,
        wrapmode=WrapMode.CHAR,
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.shape()
    pdf.ln(4)
    _who(pdf)
    commit = r["commit"] if r["real_commit"] else L["local_commit"]
    pdf.para(f"{L['fact_commit']} {pdf.ltr(commit)}", size=9, colour=MUTED)
    pdf.ln(5)

    # Verdict and key numbers.
    if r["assessed"]:
        _band(pdf, BAND.get(r["verdict"], GREY), r["verdict_label"], L["verdict_line"])
        if L["outdated"]:
            rescan = f" {L['rescan']}: {r['rescan_url']}" if r["rescan_url"] else ""
            pdf.note(L["outdated"] + rescan, AMBER_BG)
        tally = r["tally"]
        tiles = [
            (str(r["sites"]), L["k_sites"], None, False),
            (
                str(tally["vulnerable"]),
                L["k_vulnerable"],
                RED if tally["vulnerable"] else None,
                False,
            ),
            (str(tally["weak"]), L["k_weak"], AMBER if tally["weak"] else None, False),
            (str(r["earliest"] or "-"), L["k_earliest"], None, False),
        ]
    else:
        body = L["legacy"] + (f" {L['rescan']}: {r['rescan_url']}" if r["rescan_url"] else "")
        _band(pdf, AMBER, r["verdict_label"], body)
        tiles = [
            (str(r["findings_all"]), L["k_calls"], None, False),
            (str(r["findings_total"]), L["k_review"], RED if r["findings_total"] else None, False),
            (L["not_measured"], L["k_earliest"], None, True),
        ]
    _tiles(pdf, tiles)
    _strip(pdf, L["k_entries"], L["k_entries_value"])

    # The executive summary: what to do, in order.
    if r["actions"]:
        pdf.subheading(L["actions"])
        for action in r["actions"]:
            _action(pdf, action)


def _action(pdf: ReportPDF, a: dict[str, Any]) -> None:
    pill_w = 32
    body_w = pdf.width - 8 - pill_w - 4
    height = (
        pdf.lines(body_w, a["title"], 9.5, "B") * 5
        + pdf.lines(body_w, a["body"], 8.4) * 4.3
        + pdf.lines(body_w, a["sources_line"], 7.4) * 3.8
        + 6
    )
    pdf.space(height)
    y = pdf.get_y()
    pdf.set_font("Mono", "", 8.5)
    pdf.set_text_color(*SUBTLE)
    pdf.set_xy(pdf.at(0, 6), y + 0.6)
    pdf.cell(6, 5, str(a["rank"]), align=pdf.start)
    pdf.set_xy(pdf.at(8, body_w), y)
    pdf.set_font("Sans", "B", 9.5)
    pdf.set_text_color(*INK)
    pdf.multi_cell(body_w, 5, a["title"], align=pdf.start, new_x=XPos.LEFT, new_y=YPos.NEXT)
    pdf.set_x(pdf.at(8, body_w))
    pdf.set_font("Sans", "", 8.4)
    pdf.set_text_color(*MUTED)
    pdf.multi_cell(body_w, 4.3, a["body"], align=pdf.start, new_x=XPos.LEFT, new_y=YPos.NEXT)
    pdf.set_x(pdf.at(8, body_w))
    pdf.set_font("Sans", "", 7.4)
    pdf.set_text_color(*SUBTLE)
    pdf.multi_cell(
        body_w, 3.8, a["sources_line"], align=pdf.start, new_x=XPos.LEFT, new_y=YPos.NEXT
    )
    colour, tint = (RED, DEL_BG) if a["overdue"] else (AMBER_INK, AMBER_BG)
    pdf.set_font("Sans", "B", 7.8)
    pill = min(pill_w, pdf.get_string_width(a["when"]) + 6)
    x = pdf.at(pdf.width - pill, pill)
    pdf.set_fill_color(*tint)
    pdf.rect(x, y + 0.4, pill, 5.2, style="F", round_corners=True, corner_radius=2.6)
    pdf.set_text_color(*colour)
    pdf.set_xy(x, y + 0.7)
    pdf.cell(pill, 4.6, a["when"], align="C")
    pdf.set_font("Sans", "", 7.6)
    pdf.set_text_color(*MUTED)
    pdf.set_xy(pdf.at(pdf.width - pill_w, pill_w), y + 7)
    pdf.cell(pill_w, 4, a["sites_label"], align=pdf.end)
    end = y + height
    pdf.set_draw_color(*LINE)
    pdf.line(pdf.l_margin, end - 1.5, pdf.w - pdf.r_margin, end - 1.5)
    pdf.set_y(end + 1)


def _stacked_bar(pdf: ReportPDF) -> None:
    r = pdf.r
    pdf.space(24)
    y = pdf.get_y() + 1
    x = 0.0
    pdf.set_fill_color(*SOFT)
    pdf.rect(pdf.l_margin, y, pdf.width, 3.4, style="F", round_corners=True, corner_radius=1.7)
    for status in ("vulnerable", "weak", "review", "pq", "safe"):
        share = r["tally"][status] / r["sites"]
        if share:
            w = pdf.width * share
            pdf.set_fill_color(*STATUS[status])
            pdf.rect(pdf.at(x, w), y, w, 3.4, style="F")
            x += w
    line_y = y + 6
    pdf.set_font("Sans", "", 8.2)
    offset = 0.0
    for status in ("vulnerable", "weak", "review", "pq", "safe"):
        text = f"{r['tally_labels'][status]}: {r['tally'][status]}"
        w = pdf.get_string_width(text) + 5
        if offset + w > pdf.width:
            offset = 0.0
            line_y += 5
        box = pdf.at(offset, w)
        pdf.set_fill_color(*STATUS[status])
        pdf.ellipse(box + (w - 2.2 if pdf.rtl else 0), line_y + 1.4, 2.2, 2.2, style="F")
        pdf.set_text_color(*INK)
        pdf.set_xy(box + (0 if pdf.rtl else 3.2), line_y)
        pdf.cell(w - 3.2, 5, text, align=pdf.start)
        offset += w + 4
    pdf.set_y(line_y + 7)


def _diff(pdf: ReportPDF, patch: dict[str, Any]) -> None:
    size = 7.4
    number_w, kind_w = 11, 4
    text_w = pdf.width - number_w - kind_w - 4
    heights = [
        pdf.lines(text_w, line["text"] or " ", size, font="Mono") * 3.9 + 0.8
        for line in patch["lines"]
    ]
    pdf.space(min(7 + sum(heights) + 2, 80))
    pdf.shape(ltr=True)
    x0 = pdf.l_margin
    y = pdf.get_y()
    pdf.set_draw_color(*LINE)
    pdf.set_fill_color(*SOFT)
    pdf.rect(x0, y, pdf.width, 7, style="DF")
    pdf.set_font("Mono", "", 7.8)
    pdf.set_text_color(*INK)
    pdf.set_xy(x0 + 3, y + 1.3)
    pdf.cell(pdf.width - 6, 4.5, _clean(patch["where"]), align="L")
    pdf.set_y(y + 7)
    for line, height in zip(patch["lines"], heights, strict=True):
        if pdf.get_y() + height > pdf.h - pdf.b_margin:
            pdf.add_page()
            pdf.shape(ltr=True)
        y = pdf.get_y()
        bg = DEL_BG if line["kind"] == "-" else ADD_BG if line["kind"] == "+" else WHITE
        pdf.set_fill_color(*bg)
        pdf.rect(x0, y, pdf.width, height, style="F")
        pdf.set_font("Mono", "", size)
        pdf.set_text_color(*SUBTLE)
        pdf.set_xy(x0, y + 0.4)
        pdf.cell(number_w, 3.9, str(line["no"]), align="R")
        kind = RED if line["kind"] == "-" else GREEN if line["kind"] == "+" else SUBTLE
        pdf.set_text_color(*kind)
        pdf.set_xy(x0 + number_w + 1, y + 0.4)
        pdf.cell(kind_w, 3.9, line["kind"].strip(), align="C")
        pdf.set_text_color(*INK)
        pdf.set_xy(x0 + number_w + kind_w + 2, y + 0.4)
        pdf.multi_cell(
            text_w,
            3.9,
            _clean(line["text"]) or " ",
            align="L",
            wrapmode=WrapMode.CHAR,
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        pdf.set_y(y + height)
    pdf.set_draw_color(*LINE)
    pdf.line(x0, pdf.get_y(), x0 + pdf.width, pdf.get_y())
    pdf.shape()
    pdf.ln(4)


def _factor(pdf: ReportPDF, f: dict[str, Any]) -> None:
    meter_w, lost_w = 36, 14
    text_w = pdf.width - meter_w - lost_w - 8
    cites = " · ".join(f["citations"])
    height = (
        pdf.lines(text_w, f["name"], 9.5, "B") * 5
        + pdf.lines(text_w, f["why"], 8.2) * 4.2
        + (pdf.lines(text_w, cites, 7.2, font="Mono") * 3.6 if cites else 0)
        + 4
    )
    pdf.space(height)
    y = pdf.get_y()
    pdf.set_xy(pdf.at(0, text_w), y)
    pdf.set_font("Sans", "B", 9.5)
    pdf.set_text_color(*INK)
    pdf.multi_cell(text_w, 5, f["name"], align=pdf.start, new_x=XPos.LEFT, new_y=YPos.NEXT)
    pdf.set_x(pdf.at(0, text_w))
    pdf.set_font("Sans", "", 8.2)
    pdf.set_text_color(*MUTED)
    pdf.multi_cell(text_w, 4.2, f["why"], align=pdf.start, new_x=XPos.LEFT, new_y=YPos.NEXT)
    if cites:
        pdf.shape(ltr=True)
        pdf.set_x(pdf.at(0, text_w))
        pdf.set_font("Mono", "", 7.2)
        pdf.set_text_color(*SUBTLE)
        pdf.multi_cell(
            text_w,
            3.6,
            cites,
            align=pdf.start,
            wrapmode=WrapMode.CHAR,
            new_x=XPos.LEFT,
            new_y=YPos.NEXT,
        )
        pdf.shape()
    mx = pdf.at(text_w + 4, meter_w)
    pdf.set_fill_color(*SOFT)
    pdf.rect(mx, y + 2, meter_w, 2, style="F", round_corners=True, corner_radius=1)
    filled = meter_w * max(0.0, min(1.0, f["value"]))
    if filled:
        pdf.set_fill_color(*INK)
        pdf.rect(mx + (meter_w - filled if pdf.rtl else 0), y + 2, filled, 2, style="F")
    if f["lost"]:
        pdf.shape(ltr=True)
        pdf.set_font("Mono", "", 8)
        pdf.set_text_color(*MUTED)
        pdf.set_xy(pdf.at(pdf.width - lost_w, lost_w), y + 0.5)
        pdf.cell(lost_w, 4, f"-{f['lost']:.1f}", align=pdf.end)
        pdf.shape()
    end = y + height
    pdf.set_draw_color(*LINE)
    pdf.line(pdf.l_margin, end - 1, pdf.w - pdf.r_margin, end - 1)
    pdf.set_y(end + 1)


def render_pdf(r: dict[str, Any], paper: str = "a4") -> bytes:
    """Render the report dictionary from ``core/report_data.build`` to PDF bytes."""
    # Two passes: the first counts the pages that "Page N of M" needs.
    first = _render(r, paper, 0)
    return bytes(_render(r, paper, first.pages_count).output())


def _render(r: dict[str, Any], paper: str, total: int) -> ReportPDF:
    L = r["L"]  # noqa: N806 (every sentence, from site.json)
    pdf = ReportPDF(r, paper, total)
    pdf.add_page()
    _cover(pdf)

    # 1. Readiness ----------------------------------------------------------------------------
    pdf.add_page()
    pdf.section(1, L["s1"])
    if not r["assessed"]:
        pdf.para(L["not_assessed_body"], colour=MUTED)
        if r["rescan_url"]:
            pdf.para(f"{L['rescan']}: {r['rescan_url']}", size=9, colour=BLUE)
    else:
        pdf.para(L["verdict_line"], colour=MUTED)
        if r["implements"]:
            pdf.note(f"{L['implements']} {L['implements_body']}")
        if r["truncation"]:
            pdf.note(f"{L['partial_title']} {L['truncation']}", AMBER_BG)
        if not r["complete"]:
            pdf.note(f"{L['partial_title']} {L['partial']}", AMBER_BG)
        if r["sites"]:
            _stacked_bar(pdf)
            pdf.para(L["counted"], size=8.2, colour=MUTED)

    # 2. Findings ------------------------------------------------------------------------------
    pdf.section(2, L["s2"])
    if r["findings"]:
        pdf.para(L["findings_note"], size=8.4, colour=MUTED)
        styles: list[list[FontFace | None]] = [
            [
                None,
                None,
                None,
                FontFace(
                    color=RED if f["status"] == "vulnerable" else AMBER,
                    emphasis="BOLD",
                    size_pt=7.8,
                ),
                None,
            ]
            for f in r["findings"]
        ]
        pdf.table_of(
            [L["col_where"], L["col_call"], L["col_algorithm"], L["col_status"], L["col_entry"]],
            [
                [f["where"], f["name"], f["algorithm"], f["status_label"], f["entry"]]
                for f in r["findings"]
            ],
            (44, 52, 17, 38, 21),
            styles=styles,
            mono={0, 1, 2},
        )
    else:
        pdf.para(L["findings_none"], colour=MUTED)

    # 3. Changes -------------------------------------------------------------------------------
    pdf.section(3, L["s3"])
    pdf.para(L["changes_lede"], colour=MUTED)
    pdf.para(L["changes_counts"], size=8.4, colour=MUTED)
    if r["patches"]:
        pdf.subheading(L["patches"], keep=50)
        for patch in r["patches"]:
            _diff(pdf, patch)
        pdf.para(L["patches_more"], size=8.4, colour=MUTED)
    if r["guides"]:
        pdf.subheading(L["guides"], keep=64)
        for guide in r["guides"]:
            pdf.space(40)
            pdf.para(f"{guide['title']}  ·  {guide['sites_label']}", size=10, style="B")
            pdf.para(f"{guide['body']} {guide['target']}", size=8.8, colour=MUTED)
            pdf.code(guide["example"])
            pdf.shape(ltr=True)
            pdf.set_font("Mono", "", 7.2)
            pdf.set_text_color(*MUTED)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(
                pdf.width,
                3.8,
                guide["sites_line"],
                align=pdf.start,
                wrapmode=WrapMode.CHAR,
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            pdf.shape()
            pdf.ln(1)
            pdf.para(guide["sources_line"], size=7.6, colour=SUBTLE)
            pdf.ln(2)
    if r["refusals"]:
        pdf.subheading(L["refusals"], keep=40)
        pdf.table_of(
            [L["col_where"], L["col_reason"]],
            [[x["where"], f"{x['title']}. {x['detail']}"] for x in r["refusals"]],
            (52, 122),
            mono={0},
        )

    # 4. Deadlines -----------------------------------------------------------------------------
    pdf.section(4, L["s4"])
    if r["deadlines"]:
        state_styles: list[list[FontFace | None]] = [
            [
                FontFace(emphasis="BOLD"),
                None,
                None,
                None,
                FontFace(color=RED if d["state"] == "overdue" else AMBER, emphasis="BOLD"),
            ]
            for d in r["deadlines"]
        ]
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
            (28, 92, 18, 12, 24),
            styles=state_styles,
        )
        pdf.para(L["deadlines_note"], size=8.2, colour=MUTED)
    else:
        pdf.para(L["deadlines_none"], colour=MUTED)

    # 5. Agility score -------------------------------------------------------------------------
    pdf.section(5, L["s5"])
    agility = r["agility"]
    if agility["factors"] and r["score_status"] == "scored" and r["agility_score"] is not None:
        pdf.para(L["agility_lede"], colour=MUTED)
        pdf.set_font("Sans", "B", 24)
        pdf.set_text_color(*INK)
        pdf.set_x(pdf.l_margin)
        pdf.cell(
            pdf.width,
            11,
            pdf.ltr(f"{r['agility_score']:.1f} / 100"),
            align=pdf.start,
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        pdf.ln(2)
        for factor in agility["factors"]:
            _factor(pdf, factor)
    else:
        pdf.para(L["m_score_value"], colour=MUTED)

    # 6. Method --------------------------------------------------------------------------------
    pdf.section(6, L["s6"])
    pdf.table_of(
        None,
        [
            [L["m_files"], L["m_files_value"]],
            [L["m_how"], L["m_how_value"]],
            [L["m_readiness"], L["m_readiness_value"]],
            [L["m_versions"], L["m_versions_value"]],
        ],
        (34, 140),
    )
    pdf.para(L["scope"], size=8.2, colour=MUTED)
    pdf.para(L["footer"], size=7.6, colour=SUBTLE)
    return pdf
