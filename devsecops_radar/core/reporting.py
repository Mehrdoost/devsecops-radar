import datetime
import re
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def redact_sensitive(text: str, patterns: list[str] = None) -> str:
    if patterns is None:
        patterns = [
            r'(?i)(password|secret|token|key)\s*[:=]\s*\S+',
            r'ghp_[a-zA-Z0-9]{36}',
            r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'
        ]
    for pat in patterns:
        text = re.sub(pat, '***REDACTED***', text)
    return text

def generate_pdf_report(
    findings: list[dict[str, Any]],
    ai_summary: dict[str, Any],
    output_file: str = "report.pdf",
    redact: bool = True,
):
    doc = SimpleDocTemplate(output_file, pagesize=A4,
                            leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
    elements = []
    styles = getSampleStyleSheet()
    # Custom cell style for table text
    cell_style = ParagraphStyle('CellStyle', parent=styles['Normal'],
                                fontSize=8, leading=10, wordWrap='CJK')
    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'],
                                 textColor=colors.HexColor('#0A0E17'),
                                 fontSize=22, spaceAfter=12)
    elements.append(Paragraph("Pipeline Sentinel — Security Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        styles['Normal']))
    elements.append(Spacer(1, 20))

    if ai_summary.get("executive_summary"):
        elements.append(Paragraph("Executive Summary", styles['Heading2']))
        summary = ai_summary['executive_summary']
        if redact:
            summary = redact_sensitive(summary)
        elements.append(Paragraph(summary, styles['Normal']))
        if ai_summary.get("risk_score"):
            elements.append(Paragraph(
                f"Risk Score: {ai_summary['risk_score']}/100", styles['Normal']))
        elements.append(Spacer(1, 16))

    elements.append(Paragraph("Findings", styles['Heading2']))
    if findings:
        # Build table data with Paragraphs for word wrapping
        table_data = []
        header = [Paragraph("<b>Tool</b>", cell_style),
                  Paragraph("<b>ID</b>", cell_style),
                  Paragraph("<b>Severity</b>", cell_style),
                  Paragraph("<b>Target</b>", cell_style),
                  Paragraph("<b>Title</b>", cell_style)]
        table_data.append(header)
        for f in findings[:50]:
            title = f.get('title', '')
            if redact:
                title = redact_sensitive(title)
            row = [
                Paragraph(f.get('tool', ''), cell_style),
                Paragraph(f.get('id', ''), cell_style),
                Paragraph(f.get('severity', ''), cell_style),
                Paragraph(redact_sensitive(f.get('target', '')) if redact else f.get('target', ''), cell_style),
                Paragraph(title[:100], cell_style)  # limit title length for display
            ]
            table_data.append(row)

        # Column widths: proportional to content
        col_widths = [60, 120, 55, 120, 170]
        t = Table(table_data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0A0E17')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F4F6F8')]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No findings.", styles['Normal']))

    doc.build(elements)
    print(f"[REPORT] PDF saved to {output_file}")
