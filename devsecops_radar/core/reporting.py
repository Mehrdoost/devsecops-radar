import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

COMPLIANCE_MAP: dict[str, list[str]] = {
    "CIS": [
        "CIS Control 1: Inventory and Control of Enterprise Assets",
        "CIS Control 3: Data Protection",
        "CIS Control 7: Continuous Vulnerability Management",
        "CIS Control 16: Application Software Security",
    ],
    "PCI-DSS": [
        "PCI DSS 6.5: Address common coding vulnerabilities",
        "PCI DSS 11.2: Run internal and external network vulnerability scans",
    ],
    "ISO27001": [
        "ISO 27001 A.12.6: Technical Vulnerability Management",
        "ISO 27001 A.14.2: Security in Development and Support Processes",
    ],
}


def _validate_output_path(output_file: str, base_dir: Path | None = None) -> Path:
    if base_dir is None:
        base_dir = Path.cwd()
    else:
        base_dir = base_dir.resolve()
    target_path = (base_dir / output_file).resolve()
    if not target_path.is_relative_to(base_dir):
        raise ValueError(
            f"Security violation: output file path '{output_file}' escapes "
            f"the allowed directory {base_dir}"
        )
    return target_path


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


def generate_pdf_report(
    findings: list[dict[str, Any]],
    ai_summary: dict[str, Any],
    output_file: str = "report.pdf",
    redact: bool = True,
    base_dir: Path | None = None,
    framework: str | None = None,
) -> None:
    safe_path = _validate_output_path(output_file, base_dir)

    doc = SimpleDocTemplate(
        str(safe_path),
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=40,
    )
    elements = []
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
    elements.append(Paragraph(f"Generated: {generated_time}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    # Compliance mapping (if framework is selected)
    if framework and framework.upper() in COMPLIANCE_MAP:
        elements.append(Paragraph("Compliance Mapping", styles["Heading2"]))
        elements.append(Paragraph(
            f"Framework: {framework.upper()}",
            styles["Normal"],
        ))
        controls = COMPLIANCE_MAP[framework.upper()]
        for ctrl in controls:
            elements.append(Paragraph(f"• {ctrl}", styles["Normal"]))
        elements.append(Spacer(1, 16))

    # Executive summary (AI)
    if ai_summary.get("executive_summary"):
        elements.append(Paragraph("Executive Summary", styles["Heading2"]))
        summary = ai_summary["executive_summary"]
        if redact:
            summary = redact_sensitive(summary)
        elements.append(Paragraph(summary, styles["Normal"]))
        if ai_summary.get("risk_score"):
            elements.append(
                Paragraph(
                    f"Risk Score: {ai_summary['risk_score']}/100",
                    styles["Normal"],
                )
            )
        elements.append(Spacer(1, 16))

    # Findings table
    elements.append(Paragraph("Findings", styles["Heading2"]))
    if findings:
        table_data = []
        header = [
            Paragraph("<b>Tool</b>", cell_style),
            Paragraph("<b>ID</b>", cell_style),
            Paragraph("<b>Severity</b>", cell_style),
            Paragraph("<b>Target</b>", cell_style),
            Paragraph("<b>Title</b>", cell_style),
        ]
        table_data.append(header)

        for f in findings[:50]:
            tool = f.get("tool", "")
            fid = f.get("id", "")
            title = f.get("title", "")
            target = f.get("target", "")

            if redact:
                tool = redact_sensitive(tool)
                fid = redact_sensitive(fid)
                title = redact_sensitive(title)
                target = redact_sensitive(target)

            row = [
                Paragraph(tool, cell_style),
                Paragraph(fid, cell_style),
                Paragraph(f.get("severity", ""), cell_style),
                Paragraph(target, cell_style),
                Paragraph(
                    (title[:100] + "..." if len(title) > 100 else title),
                    cell_style,
                ),
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
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#F4F6F8")],
                    ),
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

    try:
        doc.build(elements)
        logger.success(f"PDF report saved to {safe_path}")
    except Exception as e:
        logger.error(f"Failed to build PDF report: {e}")
        raise RuntimeError("PDF generation failed") from e
