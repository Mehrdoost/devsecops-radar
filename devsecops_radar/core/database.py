from datetime import UTC, datetime
from typing import Any

from loguru import logger
from sqlalchemy.orm import scoped_session

from devsecops_radar.core.models import (
    Finding,
    Scan,
    SessionLocal,
)
from devsecops_radar.core.models import (
    init_db as models_init_db,
)

db_session = scoped_session(SessionLocal)

_tables_initialized = False


def init_db() -> None:
    """Ensure all tables exist. Safe to call multiple times."""
    global _tables_initialized
    if not _tables_initialized:
        models_init_db()
        _tables_initialized = True
    logger.info("Database tables and constraints verified.")


def _truncate_string(value: str, max_length: int = 2000) -> str:
    """Prevent log/DB bloat from oversized fields."""
    if value and len(value) > max_length:
        return value[:max_length]
    return value


def _safe_float(value: Any) -> float | None:
    """Convert a value to float, handling strings like '120s'."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        clean = value.strip().rstrip("s")
        try:
            return float(clean)
        except ValueError:
            logger.warning(f"Could not convert execution_time '{value}' to float.")
            return None
    return None


def _safe_int(value: Any) -> int | None:
    """Safely convert a value to int, returning None if invalid."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def save_scan(
    findings: list[dict[str, Any]],
    ai_summary: dict[str, Any] | None = None,
) -> None:
    """Persist a scan and its findings atomically."""
    init_db()

    session = db_session()
    try:
        exec_time = _safe_float(
            ai_summary.get("execution_time") if ai_summary else None
        )

        new_scan = Scan(
            timestamp=datetime.now(UTC),
            risk_score=ai_summary.get("risk_score") if ai_summary else None,
            hardware_profile=ai_summary.get("hardware_profile") if ai_summary else None,
            execution_time=exec_time,
        )
        session.add(new_scan)
        session.flush()

        for f in findings:
            new_finding = Finding(
                scan_id=new_scan.id,
                tool=_truncate_string(f.get("tool", "UNKNOWN")),
                rule_id=f.get("id", "UNKNOWN"),
                severity=f.get("severity", "LOW").upper(),
                target=_truncate_string(f.get("target", "UNKNOWN"), 1000),
                title=_truncate_string(f.get("title", ""), 500),
                description=_truncate_string(f.get("description", ""), 2000),
                line=_safe_int(f.get("line")),
                dynamic_risk_score=f.get("dynamic_risk_score", 0.0),
            )
            session.add(new_finding)

        session.commit()
        logger.success(f"Scan {new_scan.id} saved with {len(findings)} findings.")
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to save scan: {e}")
        raise


def get_all_scans() -> list[dict[str, Any]]:
    session = db_session()
    scans = session.query(Scan).order_by(Scan.timestamp.desc()).all()
    return [
        {
            "scan_id": s.id,
            "timestamp": s.timestamp.isoformat() if s.timestamp else None,
            "risk_score": s.risk_score,
            "hardware_profile": s.hardware_profile,
        }
        for s in scans
    ]


def get_scan_by_id(scan_id: int) -> dict[str, Any] | None:
    session = db_session()
    scan = session.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return None
    findings_list = [
        {
            "finding_db_id": f.id,
            "tool": f.tool,
            "id": f.rule_id,
            "severity": f.severity,
            "target": f.target,
            "title": f.title,
            "description": f.description,
        }
        for f in scan.findings
    ]
    return {
        "scan_id": scan.id,
        "timestamp": scan.timestamp.isoformat() if scan.timestamp else None,
        "risk_score": scan.risk_score,
        "hardware_profile": scan.hardware_profile,
        "execution_time": scan.execution_time,
        "findings": findings_list,
    }


def get_findings_paginated(page: int = 1, per_page: int = 50) -> dict[str, Any]:
    per_page = max(1, min(per_page, 100))
    page = max(1, page)

    session = db_session()
    total = session.query(Finding).count()
    findings = (
        session.query(Finding)
        .order_by(Finding.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "data": [
            {
                "scan_id": f.scan_id,
                "tool": f.tool,
                "id": f.rule_id,
                "severity": f.severity,
                "target": f.target,
                "title": f.title,
            }
            for f in findings
        ],
    }


def compare_scans(scan_id1: int, scan_id2: int) -> dict[str, Any]:
    s1 = get_scan_by_id(scan_id1)
    s2 = get_scan_by_id(scan_id2)
    if not s1 or not s2:
        return {"error": "One or both scans not found"}

    def _make_hash(finding: dict) -> str:
        return (
            f"{finding.get('tool','')}|{finding.get('id','')}|"
            f"{finding.get('target','')}|{finding.get('severity','')}"
        )

    hashes1 = {_make_hash(f): f for f in s1.get("findings", [])}
    hashes2 = {_make_hash(f): f for f in s2.get("findings", [])}
    added = [hashes2[h] for h in (set(hashes2.keys()) - set(hashes1.keys()))]
    removed = [hashes1[h] for h in (set(hashes1.keys()) - set(hashes2.keys()))]
    return {"scan_id1": scan_id1, "scan_id2": scan_id2, "added": added, "removed": removed}
