import json
import os
from datetime import datetime
from typing import List, Dict, Any

def generate_pdf_report(findings: List[Dict[str, Any]], ai_summary: Dict[str, Any], output_file: str = "report.pdf"):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
    except ImportError:
        print("[ERROR] reportlab not installed. Install with 'pip install reportlab'")
        return

    doc = SimpleDocTemplate(output_file, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    # Title
    elements.append(Paragraph("Pipeline Sentinel Security Report", styles['Title']))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))

    # Executive Summary
    if ai_summary.get("executive_summary"):
        elements.append(Paragraph("Executive Summary", styles['Heading2']))
        elements.append(Paragraph(ai_summary['executive_summary'], styles['Normal']))
        if ai_summary.get("risk_score"):
            elements.append(Paragraph(f"Risk Score: {ai_summary['risk_score']}/100", styles['Normal']))

    # Findings Table
    if findings:
        elements.append(Paragraph("Findings", styles['Heading2']))
        table_data = [["Tool", "ID", "Severity", "Target", "Title"]]
        for f in findings[:50]:  # limit rows
            table_data.append([
                f.get('tool',''),
                f.get('id',''),
                f.get('severity',''),
                f.get('target',''),
                f.get('title','')[:80]
            ])
        t = Table(table_data)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0), colors.whitesmoke),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        elements.append(t)

    doc.build(elements)
    print(f"[REPORT] PDF saved to {output_file}")