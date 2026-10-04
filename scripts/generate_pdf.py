#!/usr/bin/env python3
import argparse, csv
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A3, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

SEVS = ["Critical", "High", "Medium", "Low", "Warning", "Note", "Error", "N/A"]
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="SmallX", parent=styles["BodyText"], fontSize=7, leading=9, textColor=colors.HexColor("#344054")))
styles.add(ParagraphStyle(name="MetricX", parent=styles["Heading2"], fontSize=20, alignment=TA_CENTER))
styles.add(ParagraphStyle(name="LabelX", parent=styles["BodyText"], fontSize=7, alignment=TA_CENTER, textColor=colors.HexColor("#667085")))

def read_rows(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def severity(row):
    x = (row.get("Security Severity") or "").strip()
    return x.title() if x and x.lower() != "n/a" else (row.get("Severity") or "N/A").title()

def short(value, length):
    value = " ".join(str(value or "").split())
    return value if len(value) <= length else value[:length - 1] + "…"

def header_footer(canvas, doc, title, classification):
    w, h = landscape(A3)
    canvas.saveState()
    canvas.setFillColor(colors.HexColor("#101828"))
    canvas.rect(0, h - 17 * mm, w, 17 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(12 * mm, h - 11 * mm, title)
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(w - 12 * mm, h - 11 * mm, classification)
    canvas.setStrokeColor(colors.HexColor("#D0D5DD"))
    canvas.line(12 * mm, 13 * mm, w - 12 * mm, 13 * mm)
    canvas.setFillColor(colors.HexColor("#667085"))
    canvas.drawString(12 * mm, 7 * mm, "Generated from GitHub Code Scanning / CodeQL REST API")
    canvas.drawRightString(w - 12 * mm, 7 * mm, f"Page {doc.page}")
    canvas.restoreState()

def metric(label, value):
    return Table(
        [[Paragraph(escape(str(value)), styles["MetricX"])],
         [Paragraph(escape(label), styles["LabelX"])]],
        colWidths=[48 * mm], rowHeights=[13 * mm, 8 * mm],
        style=TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D0D5DD")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F9FAFB")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]),
    )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--title", default="CodeQL C/C++ Security Report")
    parser.add_argument("--classification", default="Confidential - Security")
    parser.add_argument("--team", default="Application Security")
    parser.add_argument("--business-unit", default="Engineering")
    args = parser.parse_args()

    rows = read_rows(args.input)
    counts = Counter(severity(r) for r in rows)
    statuses = Counter(r.get("Status", "Unknown") for r in rows)

    page_w, page_h = landscape(A3)
    doc = BaseDocTemplate(
        str(args.output), pagesize=landscape(A3),
        leftMargin=12 * mm, rightMargin=12 * mm,
        topMargin=24 * mm, bottomMargin=18 * mm,
        title=args.title,
    )
    frame = Frame(12 * mm, 18 * mm, page_w - 24 * mm, page_h - 38 * mm, id="main")
    doc.addPageTemplates([
        PageTemplate(
            id="report", frames=frame,
            onPage=lambda c, d: header_footer(c, d, args.title, args.classification),
        )
    ])

    story = [
        Paragraph(escape(args.title), styles["Title"]),
        Paragraph(
            f"<b>Team:</b> {escape(args.team)} &nbsp; "
            f"<b>Business Unit:</b> {escape(args.business_unit)} &nbsp; "
            f"<b>Generated:</b> {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
            styles["SmallX"],
        ),
        Spacer(1, 6 * mm),
    ]

    cards = [
        metric("Total", len(rows)),
        metric("Critical", counts["Critical"]),
        metric("High", counts["High"]),
        metric("Medium", counts["Medium"]),
        metric("Low", counts["Low"]),
    ]
    cards_table = Table([cards], colWidths=[52 * mm] * 5)
    cards_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.extend([cards_table, Spacer(1, 6 * mm)])

    story.append(Paragraph("Severity distribution", styles["Heading3"]))
    chart = [["Severity", "Findings"]] + [[s, str(counts[s])] for s in SEVS if counts[s]]
    chart_table = Table(chart, colWidths=[65 * mm, 35 * mm])
    chart_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#344054")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D5DD")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
    ]))
    story.extend([chart_table, Spacer(1, 4 * mm), Paragraph("Triage status", styles["Heading3"])])

    status_table_data = [["Status", "Count"]] + [
        [k, str(v)] for k, v in sorted(statuses.items(), key=lambda x: (-x[1], x[0]))
    ]
    status_table = Table(status_table_data, colWidths=[75 * mm, 35 * mm])
    status_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#344054")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D5DD")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.extend([status_table, PageBreak(), Paragraph("Finding details", styles["Heading2"])])

    headers = [
        "Alert", "Rule", "Severity", "File / Line", "State",
        "Assignee / Owner", "Dismissed By", "Reason", "Triage Comment", "Commit"
    ]
    # Use Paragraphs so long values wrap inside their cells.
    cell_style = ParagraphStyle(
        name="FindingCell",
        parent=styles["SmallX"],
        fontSize=7.0,
        leading=8.5,
        spaceAfter=0,
        wordWrap="CJK",
    )
    header_style = ParagraphStyle(
        name="FindingHeader",
        parent=styles["SmallX"],
        fontSize=7.2,
        leading=8.5,
        textColor=colors.white,
        fontName="Helvetica-Bold",
        spaceAfter=0,
    )

    data = [[Paragraph(escape(h), header_style) for h in headers]]

    for r in rows:
        location = f'{r.get("File", "")}:{r.get("Start Line", "")}'
        cells = [
            r.get("Alert ID", ""),
            r.get("Rule ID", ""),
            severity(r),
            location,
            r.get("Status", ""),
            r.get("Assignee / Owner", ""),
            r.get("Dismissed By", ""),
            r.get("Dismissal Reason", ""),
            r.get("Triage Comment", ""),
            r.get("Commit SHA", ""),
        ]
        data.append([
            Paragraph(escape(str(value or "")), cell_style)
            for value in cells
        ])

    # A3 landscape usable width with 12 mm margins is ~396 mm.
    # The 344 mm table therefore fits without clipping while retaining
    # readable widths for security-team triage fields.
    findings = Table(
        data,
        repeatRows=1,
        colWidths=[
            16*mm,   # Alert
            48*mm,   # Rule
            24*mm,   # Severity
            60*mm,   # File / Line
            32*mm,   # State
            42*mm,   # Assignee / Owner
            32*mm,   # Dismissed By
            36*mm,   # Reason
            66*mm,   # Triage Comment
            28*mm,   # Commit
        ],
        hAlign="LEFT",
    )
    findings.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#101828")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.0),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D5DD")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.extend([findings, PageBreak(), Paragraph("Methodology and scope", styles["Heading2"])])

    for text in [
        "Source: GitHub Code Scanning REST API, filtered to CodeQL.",
        "Scope: C/C++ CodeQL query namespace cpp/* by default.",
        "The state filter is omitted so open and closed/fixed/dismissed findings are included.",
        "Triage metadata comes from the Code Scanning alert record.",
        "Assignee / Owner uses the alert assignees field when returned; otherwise Unassigned.",
        "Treat this document as confidential security information.",
    ]:
        story.extend([Paragraph("• " + escape(text), styles["SmallX"]), Spacer(1, 1.5 * mm)])

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    doc.build(story)

if __name__ == "__main__":
    main()