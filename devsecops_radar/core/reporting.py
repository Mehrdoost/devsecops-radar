import datetime
import re
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Table, TableStyle


def redact_sensitive(text: str, patterns: list[str] | None = None) -> str:
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
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    title = "Pipeline Sentinel Security Report"
    if redact:
        title += " (Sensitive Data Redacted)"
    elements.append(Paragraph(title, styles['Title']))
    elements.append(
        Paragraph(
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles['Normal'],
        )
    )

    if ai_summary.get("executive_summary"):
        summary = ai_summary['executive_summary']
        if redact:
            summary = redact_sensitive(summary)
        elements.append(Paragraph("Executive Summary", styles['Heading2']))
        elements.append(Paragraph(summary, styles['Normal']))
        if ai_summary.get("risk_score"):
            elements.append(
                Paragraph(f"Risk Score: {ai_summary['risk_score']}/100", styles['Normal'])
            )

    if findings:
        elements.append(Paragraph("Findings", styles['Heading2']))
        table_data = [["Tool", "ID", "Severity", "Target", "Title"]]
        for f in findings[:50]:
            title = f.get('title', '')
            if redact:
                title = redact_sensitive(title)
            table_data.append([
                f.get('tool', ''),
                f.get('id', ''),
                f.get('severity', ''),
                redact_sensitive(f.get('target', '')) if redact else f.get('target', ''),
                title[:80]
            ])
        t = Table(table_data)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(t)

    doc.build(elements)
    print(f"[REPORT] PDF saved to {output_file}")
