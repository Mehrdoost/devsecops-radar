import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _validate_output_path(output_file: str, base_dir: Path | None = None) -> Path:
    """
    Security check: ensure the output path stays inside the allowed directory.
    Prevents path traversal attacks (e.g., '../../etc/passwd').
    """
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
    """
    Replace high‑entropy secrets and common credential patterns with ***REDACTED***.
    """
    if patterns is None:
        patterns = [
            r'(?i)(password|secret|token|key)\s*[:=]\s*\S+',
            r'ghp_[a-zA-Z0-9]{36}',
            r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
            r'glpat-[a-zA-Z0-9\-_]+',           # GitLab personal access tokens
            r'AKIA[0-9A-Z]{16}',                 # AWS Access Key IDs (mask)
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
) -> None:
    """
    Generate a professional PDF security report.

    Args:
        findings: list of finding dicts.
        ai_summary: AI analysis summary.
        output_file: relative or absolute output filename. Traversal is prevented.
        redact: whether to sanitise sensitive data.
        base_dir: directory the output is constrained to (default: current working directory).
    """
    # Validate output path securely
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

    # Custom styles
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
    # Use timezone-aware UTC timestamp
    generated_time = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    elements.append(Paragraph(f"Generated: {generated_time}", styles["Normal"]))
    elements.append(Spacer(1, 20))

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
            # Redact all text fields that could contain secrets
            tool = f.get("tool", "")
            fid = f.get("id", "")
            title = f.get("title", "")
            target = f.get("target", "")
            description = f.get("description", "")

            if redact:
                tool = redact_sensitive(tool)
                fid = redact_sensitive(fid)
                title = redact_sensitive(title)
                target = redact_sensitive(target)
                description = redact_sensitive(description)

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
