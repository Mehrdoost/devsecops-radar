# devsecops_radar/core/reporting.py
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from devsecops_radar.core.path_security import atomic_write, resolve_safe_path

# ---------------------------------------------------------------------------
# Enhanced Compliance Mapping – now with proper type annotation
# ---------------------------------------------------------------------------
ComplianceInfo = dict[str, str | list[str] | dict[str, str]]
COMPLIANCE_MAP: dict[str, ComplianceInfo] = {
    "CIS": {
        "title": "CIS Controls",
        "controls": [
            "CIS Control 1: Inventory and Control of Enterprise Assets",
            "CIS Control 3: Data Protection",
            "CIS Control 7: Continuous Vulnerability Management",
            "CIS Control 16: Application Software Security",
        ],
        "severity_keywords": {
            "CRITICAL": "CIS Control 7: Continuous Vulnerability Management",
            "HIGH": "CIS Control 7: Continuous Vulnerability Management",
            "MEDIUM": "CIS Control 3: Data Protection",
            "LOW": "CIS Control 16: Application Software Security",
        },
    },
    "PCI-DSS": {
        "title": "PCI DSS",
        "controls": [
            "PCI DSS 6.5: Address common coding vulnerabilities",
            "PCI DSS 11.2: Run internal and external network vulnerability scans",
        ],
        "severity_keywords": {
            "CRITICAL": "PCI DSS 6.5: Address common coding vulnerabilities",
            "HIGH": "PCI DSS 6.5: Address common coding vulnerabilities",
            "MEDIUM": "PCI DSS 11.2: Run internal and external network vulnerability scans",
            "LOW": "PCI DSS 11.2: Run internal and external network vulnerability scans",
        },
    },
    "ISO27001": {
        "title": "ISO 27001",
        "controls": [
            "ISO 27001 A.12.6: Technical Vulnerability Management",
            "ISO 27001 A.14.2: Security in Development and Support Processes",
        ],
        "severity_keywords": {
            "CRITICAL": "ISO 27001 A.12.6: Technical Vulnerability Management",
            "HIGH": "ISO 27001 A.12.6: Technical Vulnerability Management",
            "MEDIUM": "ISO 27001 A.14.2: Security in Development and Support Processes",
            "LOW": "ISO 27001 A.14.2: Security in Development and Support Processes",
        },
    },
}


# ---------------------------------------------------------------------------
# XML escaping for ReportLab (unchanged)
# ---------------------------------------------------------------------------
def _escape_xml(text: str) -> str:
    """Escape special characters for safe use inside ReportLab Paragraphs."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def redact_sensitive(text: str, patterns: list[str] | None = None) -> str:
    if patterns is None:
        patterns = [
            r'(?i)(password|secret|token|key)\s*[:=]\s*\S+',
            r'ghp_[a-zA-Z0-9]{36}',
            r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
            r'glpat-[a-zA-Z0-9\-_]+',
            r'AKIA[0-9A-Z]{16}',
        ]
    for pat in patterns:
        text = re.sub(pat, '***REDACTED***', text)
    return text


# ---------------------------------------------------------------------------
# PDF generation (now with real compliance mapping and atomic write)
# ---------------------------------------------------------------------------
def generate_pdf_report(
    findings: list[dict[str, Any]],
    ai_summary: dict[str, Any],
    output_file: str = "report.pdf",
    redact: bool = True,
    base_dir: Path | None = None,
    framework: str | None = None,
) -> None:
    base = base_dir or Path.cwd()
    safe_path = resolve_safe_path(output_file, base)

    # Build the document in memory first, then atomically write to disk
    elements: list[Any] = []
    styles = getSampleStyleSheet()

    cell_style = ParagraphStyle(
        "CellStyle",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        wordWrap="CJK",
    )
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#0A0E17"),
        fontSize=22,
        spaceAfter=12,
    )

    elements.append(Paragraph("Pipeline Sentinel — Security Report", title_style))
    generated_time = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    elements.append(Paragraph(_escape_xml(generated_time), styles["Normal"]))
    elements.append(Spacer(1, 20))

    # Compliance mapping – now with finding-to-control assignment
    if framework and framework.upper() in COMPLIANCE_MAP:
        framework_info = COMPLIANCE_MAP[framework.upper()]
        elements.append(Paragraph("Compliance Mapping", styles["Heading2"]))
        elements.append(
            Paragraph(
                _escape_xml(
                    f"Framework: {framework_info['title']} ({framework.upper()})"
                ),
                styles["Normal"],
            )
        )
        elements.append(Spacer(1, 8))

        controls = framework_info.get("controls", [])
        if isinstance(controls, list):
            for ctrl in controls:
                elements.append(Paragraph(_escape_xml(f"• {ctrl}"), styles["Normal"]))
        elements.append(Spacer(1, 12))

        # Map each finding to its most relevant control
        severity_map: dict[str, str] = framework_info.get("severity_keywords", {})  # type: ignore[assignment]
        control_counts: dict[str, int] = {c: 0 for c in controls if isinstance(controls, list)}
        for f in findings:
            sev = str(f.get("severity", "UNKNOWN")).upper()
            mapped_ctrl = severity_map.get(sev)
            if mapped_ctrl and mapped_ctrl in control_counts:
                control_counts[mapped_ctrl] += 1

        elements.append(Paragraph("Findings per Control:", styles["Heading3"]))
        for ctrl, cnt in control_counts.items():
            elements.append(
                Paragraph(_escape_xml(f"• {ctrl}: {cnt} finding(s)"), styles["Normal"])
            )
        elements.append(Spacer(1, 16))

    # Executive summary
    if ai_summary.get("executive_summary"):
        elements.append(Paragraph("Executive Summary", styles["Heading2"]))
        summary = ai_summary["executive_summary"]
        if redact:
            summary = redact_sensitive(summary)
        elements.append(Paragraph(_escape_xml(summary), styles["Normal"]))
        if ai_summary.get("risk_score") is not None:
            elements.append(
                Paragraph(
                    _escape_xml(f"Risk Score: {ai_summary['risk_score']}/100"),
                    styles["Normal"],
                )
            )
        elements.append(Spacer(1, 16))

    # Findings table
    elements.append(Paragraph("Findings", styles["Heading2"]))
    if findings:
        max_rows = 50
        if len(findings) > max_rows:
            elements.append(Paragraph(
                _escape_xml(f"Showing first {max_rows} of {len(findings)} findings."),
                styles["Normal"]
            ))
        table_data: list[list[Any]] = []
        header = [
            Paragraph("<b>Tool</b>", cell_style),
            Paragraph("<b>ID</b>", cell_style),
            Paragraph("<b>Severity</b>", cell_style),
            Paragraph("<b>Target</b>", cell_style),
            Paragraph("<b>Title</b>", cell_style),
        ]
        table_data.append(header)

        for f in findings[:max_rows]:
            tool = _escape_xml(str(f.get("tool", "")))
            fid = _escape_xml(str(f.get("id", "")))
            title_raw = str(f.get("title", ""))
            target_raw = str(f.get("target", ""))
            severity = str(f.get("severity", ""))

            if redact:
                title_raw = redact_sensitive(title_raw)
                target_raw = redact_sensitive(target_raw)

            title_escaped = _escape_xml(title_raw)
            target_escaped = _escape_xml(target_raw)
            severity_escaped = _escape_xml(severity)

            display_title = (title_escaped[:100] + "..." if len(title_escaped) > 100 else title_escaped)

            row = [
                Paragraph(tool, cell_style),
                Paragraph(fid, cell_style),
                Paragraph(severity_escaped, cell_style),
                Paragraph(target_escaped, cell_style),
                Paragraph(display_title, cell_style),
            ]
            table_data.append(row)

        col_widths = [60, 120, 55, 120, 170]
        t = Table(table_data, colWidths=col_widths, repeatRows=1)
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0A0E17")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F6F8")]),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(t)
    else:
        elements.append(Paragraph("No findings.", styles["Normal"]))

    # Atomically write the PDF – note: the file object is just a temporary handle
    with atomic_write(safe_path, base_dir=base, encoding="utf-8"):
        doc = SimpleDocTemplate(
            str(safe_path),
            pagesize=A4,
            leftMargin=40,
            rightMargin=40,
            topMargin=40,
            bottomMargin=40,
        )
        doc.build(elements, canvasmaker=None)
    logger.success(f"PDF report saved to {safe_path}")
