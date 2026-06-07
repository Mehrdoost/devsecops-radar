from datetime import UTC, datetime
from typing import Any

from loguru import logger
from sqlalchemy import text
from sqlalchemy.orm import scoped_session

from devsecops_radar.core.models import (
    Finding,
    Scan,
    SessionLocal,
    engine,
)
from devsecops_radar.core.models import (
    init_db as models_init_db,
)

# Scoped session for thread‑safe web requests
db_session = scoped_session(SessionLocal)


def init_db() -> None:
    """
    Ensure all tables exist. Safe to call multiple times.
    Also enables foreign keys on the current connection.
    """
    models_init_db()  # uses the same engine now
    try:
        session = db_session()
        if "sqlite" in str(engine.url):
            session.execute(text("PRAGMA foreign_keys=ON"))
        session.close()
    except Exception as e:
        logger.warning(f"Could not enforce foreign keys: {e}")
    logger.info("Database tables and constraints verified.")


def _truncate_string(value: str, max_length: int = 2000) -> str:
    """Prevent log/DB bloat from oversized fields."""
    if value and len(value) > max_length:
        return value[:max_length]
    return value


def save_scan(
    findings: list[dict[str, Any]],
    ai_summary: dict[str, Any] | None = None,
) -> None:
    """Persist a scan and its findings atomically."""
    init_db()

    session = db_session()
    try:
        new_scan = Scan(
            timestamp=datetime.now(UTC),
            risk_score=ai_summary.get("risk_score") if ai_summary else None,
            hardware_profile=ai_summary.get("hardware_profile") if ai_summary else None,
            execution_time=ai_summary.get("execution_time") if ai_summary else None,
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
                line=f.get("line"),
            )
            session.add(new_finding)

        session.commit()
        logger.success(f"Scan {new_scan.id} saved with {len(findings)} findings.")
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to save scan: {e}")
        raise
    finally:
        session.close()


def get_all_scans() -> list[dict[str, Any]]:
    session = db_session()
    try:
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
    finally:
        session.close()


def get_scan_by_id(scan_id: int) -> dict[str, Any] | None:
    session = db_session()
    try:
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
    finally:
        session.close()


def get_findings_paginated(page: int = 1, per_page: int = 50) -> dict[str, Any]:
    per_page = max(1, min(per_page, 100))
    page = max(1, page)

    session = db_session()
    try:
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
    finally:
        session.close()


def compare_scans(scan_id1: int, scan_id2: int) -> dict[str, Any]:
    s1 = get_scan_by_id(scan_id1)
    s2 = get_scan_by_id(scan_id2)
    if not s1 or not s2:
        return {"error": "One or both scans not found"}

    def _make_hash(finding: dict) -> str:
        return (
            f"{finding.get('tool')}|{finding.get('id')}|"
            f"{finding.get('target')}|{finding.get('severity')}"
        )

    hashes1 = {_make_hash(f): f for f in s1.get("findings", [])}
    hashes2 = {_make_hash(f): f for f in s2.get("findings", [])}
    added = [hashes2[h] for h in (set(hashes2.keys()) - set(hashes1.keys()))]
    removed = [hashes1[h] for h in (set(hashes1.keys()) - set(hashes2.keys()))]
    return {"scan_id1": scan_id1, "scan_id2": scan_id2, "added": added, "removed": removed}
