from devsecops_radar.core.models import (
    init_db, SessionLocal, Scan, Finding
)
from typing import List, Dict, Any, Optional

def save_scan(findings: List[Dict[str, Any]]):
    from devsecops_radar.core.models import save_scan_to_db
    save_scan_to_db(findings)

def get_all_scans() -> List[Dict[str, Any]]:
    init_db()
    session = SessionLocal()
    scans = []
    for scan in session.query(Scan).order_by(Scan.timestamp.asc()).all():
        findings = session.query(Finding).filter(Finding.scan_id == scan.id).all()
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.severity.upper() if f.severity else "UNKNOWN"
            counts[sev] = counts.get(sev, 0) + 1
        scans.append({
            "id": scan.id,
            "timestamp": scan.timestamp.isoformat(),
            "total": len(findings),
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
        })
    session.close()
    return scans

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    session = SessionLocal()
    scan = session.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        session.close()
        return None
    findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
    findings_list = []
    for f in findings:
        findings_list.append({
            "tool": f.tool,
            "id": f.id,
            "severity": f.severity,
            "target": f.target,
            "title": f.title,
            "description": f.description,
            "line": f.line
        })
    session.close()
    return {
        "id": scan.id,
        "timestamp": scan.timestamp.isoformat(),
        "findings": findings_list,
        "total": len(findings_list)
    }

def compare_scans(scan_id_1: int, scan_id_2: int) -> Dict[str, Any]:
    scan1 = get_scan_by_id(scan_id_1)
    scan2 = get_scan_by_id(scan_id_2)
    if not scan1 or not scan2:
        return {"error": "One or both scans not found"}
    ids1 = {f.get("id") for f in scan1["findings"]}
    ids2 = {f.get("id") for f in scan2["findings"]}
    added = [f for f in scan2["findings"] if f.get("id") not in ids1]
    removed = [f for f in scan1["findings"] if f.get("id") not in ids2]
    return {
        "scan1": {"id": scan1["id"], "timestamp": scan1["timestamp"], "total": scan1["total"]},
        "scan2": {"id": scan2["id"], "timestamp": scan2["timestamp"], "total": scan2["total"]},
        "added": len(added),
        "removed": len(removed),
        "unchanged": len(scan1["findings"]) - len(removed),
        "added_findings": added,
        "removed_findings": removed,
    }

def get_findings_by_severity(severity: str, limit: int = 100) -> List[Dict[str, Any]]:
    session = SessionLocal()
    findings = session.query(Finding).filter(Finding.severity == severity.upper()).limit(limit).all()
    result = []
    for f in findings:
        result.append({
            "tool": f.tool,
            "id": f.id,
            "severity": f.severity,
            "target": f.target,
            "title": f.title,
            "description": f.description,
            "line": f.line
        })
    session.close()
    return result