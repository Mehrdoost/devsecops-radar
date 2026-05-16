from devsecops_radar.core.models import SessionLocal, Finding
from typing import List, Dict, Any

def rag_search(query: str, limit: int = 5) -> List[Dict[str, Any]]:
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