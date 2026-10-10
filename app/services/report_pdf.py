"""
OSIG Backend - PDF Report Rendering

Renders a scan and its findings into a multi-page PDF using ReportLab platypus.
"""
from collections import OrderedDict
from datetime import datetime
from typing import Any, List
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ACCENT = colors.HexColor("#1d4ed8")
MUTED = colors.HexColor("#6b7280")
BORDER = colors.HexColor("#e5e7eb")
HEADER_BG = colors.HexColor("#f3f4f6")

MAX_VALUE_CHARS = 600
MAX_LIST_ITEMS = 25


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], alignment=0, textColor=ACCENT, spaceAfter=2 * mm),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], spaceBefore=6 * mm, spaceAfter=2 * mm),
        "h3": ParagraphStyle("h3", parent=base["Heading4"], spaceBefore=3 * mm, spaceAfter=1 * mm),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=9, leading=12),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontSize=8, leading=10, textColor=MUTED),
        "cell": ParagraphStyle("cell", parent=base["BodyText"], fontSize=8, leading=10),
        "cell_key": ParagraphStyle("cell_key", parent=base["BodyText"], fontSize=8, leading=10, textColor=MUTED),
    }


def _p(text: Any, style) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def _format_value(value: Any) -> str:
    """Flatten a JSON value into readable text, truncating very long content."""
    if value is None:
        text = "—"
    elif isinstance(value, bool):
        text = "yes" if value else "no"
    elif isinstance(value, list):
        items = [_format_value(v) for v in value[:MAX_LIST_ITEMS]]
        if len(value) > MAX_LIST_ITEMS:
            items.append(f"… (+{len(value) - MAX_LIST_ITEMS} more)")
        text = ", ".join(items) if items else "—"
    elif isinstance(value, dict):
        text = "; ".join(f"{k}: {_format_value(v)}" for k, v in value.items()) or "—"
    else:
        text = str(value)
    if len(text) > MAX_VALUE_CHARS:
        text = text[:MAX_VALUE_CHARS] + "…"
    return text


def _grid(rows, col_widths, header=True) -> Table:
    table = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), HEADER_BG))
    table.setStyle(TableStyle(style))
    return table


def _on_page(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(
        doc.leftMargin, 10 * mm,
        "OSIG — compiled from publicly available sources only. Verify findings before acting on them.",
    )
    canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def render_pdf_report(file_path: str, report_name: str, scan, results: List) -> None:
    s = _styles()
    doc = SimpleDocTemplate(
        file_path, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        title=report_name, author="OSIG",
    )
    width = doc.width
    story = []

    # ── Header ────────────────────────────────────────────────
    story.append(_p(report_name, s["title"]))
    story.append(_p(f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", s["small"]))
    story.append(Spacer(1, 4 * mm))

    def ts(dt):
        return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "—"

    meta = [
        ["Target", scan.target_value],
        ["Target type", scan.target_type.value],
        ["Scan type", scan.scan_type.value],
        ["Started", ts(scan.started_at)],
        ["Completed", ts(scan.completed_at)],
        ["Total findings", str(len(results))],
    ]
    story.append(_grid(
        [[_p(k, s["cell_key"]), _p(v, s["cell"])] for k, v in meta],
        [35 * mm, width - 35 * mm], header=False,
    ))

    # ── Module summary ────────────────────────────────────────
    story.append(_p("Modules", s["h2"]))
    rows = [[_p(h, s["cell_key"]) for h in ("Module", "Status", "Findings", "Notes")]]
    for mod in scan.modules:
        rows.append([
            _p(mod.display_name or mod.name, s["cell"]),
            _p(mod.status.value, s["cell"]),
            _p(mod.result_count, s["cell"]),
            _p(mod.error or "", s["cell"]),
        ])
    story.append(_grid(rows, [55 * mm, 25 * mm, 20 * mm, width - 100 * mm]))

    story.append(_p("Findings", s["h2"]))
    story.extend(_findings(scan, results, s, width))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)

def _findings(scan, results: List, s, width) -> list:
    """Every finding, grouped by module, as flowables."""
    story = []
    if not results:
        story.append(_p("No findings were recorded for this scan.", s["body"]))

    by_module = OrderedDict()
    for r in results:
        by_module.setdefault(r.module, []).append(r)
    display_names = {m.name: (m.display_name or m.name) for m in scan.modules}

    for module_name, module_results in by_module.items():
        story.append(_p(f"{display_names.get(module_name, module_name)} ({len(module_results)})", s["h3"]))
        for r in module_results:
            heading = f"{r.data_type} · {r.source} · confidence {round(r.confidence * 100)}%"
            rows = [[_p(heading, s["cell_key"]), ""]]
            if r.source_url:
                rows.append([_p("url", s["cell_key"]), _p(r.source_url, s["cell"])])
            data = r.data if isinstance(r.data, dict) else {"value": r.data}
            for key, value in data.items():
                rows.append([_p(key, s["cell_key"]), _p(_format_value(value), s["cell"])])
            table = Table(rows, colWidths=[35 * mm, width - 35 * mm])
            table.setStyle(TableStyle([
                ("SPAN", (0, 0), (-1, 0)),
                ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("LINEBELOW", (0, 0), (-1, -2), 0.25, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            # Keep short findings on one page; let long ones split naturally
            story.append(KeepTogether([table]) if len(rows) <= 12 else table)
            story.append(Spacer(1, 2 * mm))

    return story


def render_investigation_pdf(fileobj, inv, scans_with_results) -> None:
    """One document for a whole case: notes, pins, then each scan's findings."""
    s = _styles()
    doc = SimpleDocTemplate(
        fileobj, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        title=inv.name, author="OSIG",
    )
    width = doc.width
    story = [
        _p(inv.name, s["title"]),
        _p(f"Investigation · generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", s["small"]),
        Spacer(1, 4 * mm),
    ]
    if inv.tags:
        story.append(_p("Tags: " + ", ".join(inv.tags), s["body"]))
    if inv.notes:
        story.append(_p("Notes", s["h2"]))
        for para in str(inv.notes).split("\n\n"):
            story.append(_p(para, s["body"]))

    story.append(_p("Scans", s["h2"]))
    rows = [[_p(h, s["cell_key"]) for h in ("Target", "Type", "Depth", "Findings", "Pivoted from")]]
    for scan, results in scans_with_results:
        rows.append([_p(scan.target_value, s["cell"]), _p(scan.target_type.value, s["cell"]),
                     _p(scan.scan_type.value, s["cell"]), _p(len(results), s["cell"]),
                     _p((scan.pivot_entity or "—").split(":", 1)[-1], s["cell"])])
    story.append(_grid(rows, [50 * mm, 22 * mm, 18 * mm, 18 * mm, width - 108 * mm]))

    if inv.pins:
        story.append(_p("Pinned findings", s["h2"]))
        rows = [[_p(h, s["cell_key"]) for h in ("Entity", "Kind", "Note")]]
        for pin in inv.pins:
            rows.append([_p(pin.label, s["cell"]), _p(pin.kind, s["cell"]), _p(pin.note or "", s["cell"])])
        story.append(_grid(rows, [60 * mm, 25 * mm, width - 85 * mm]))

    for scan, results in scans_with_results:
        story.append(_p(f"{scan.target_value} — {scan.scan_type.value} {scan.target_type.value} scan", s["h2"]))
        story.extend(_findings(scan, sorted(results, key=lambda r: (r.module, r.data_type)), s, width))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
