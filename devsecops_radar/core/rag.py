from typing import Any

from devsecops_radar.core.models import Finding, SessionLocal


def rag_search(query: str, limit: int = 5) -> list[dict[str, Any]]:
    session = SessionLocal()
    results = session.query(Finding).filter(
        Finding.title.ilike(f'%{query}%') | Finding.description.ilike(f'%{query}%')
    ).order_by(Finding.id.desc()).limit(limit).all()
    findings = []
    for f in results:
        findings.append({
            "tool": f.tool,
            "id": f.id,
            "severity": f.severity,
            "target": f.target,
            "title": f.title,
            "description": f.description,
            "line": f.line
        })
    session.close()
    return findings
