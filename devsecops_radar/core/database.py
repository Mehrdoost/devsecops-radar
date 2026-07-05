# devsecops_radar/core/database.py
"""
Database persistence layer with strict session management,
ORM‑safe batch inserts, and memory‑efficient comparison.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from threading import Lock
from typing import Any

from loguru import logger
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import scoped_session

from devsecops_radar.core.models import (
    Finding,
    FindingSchema,
    Scan,
    SessionLocal,
)
from devsecops_radar.core.models import init_db as models_init_db

# ---------------------------------------------------------------------------
# Thread‑safe scoped session (used only for teardown compatibility)
# ---------------------------------------------------------------------------
db_session = scoped_session(SessionLocal)

_tables_initialized = False
_tables_lock = Lock()


def init_db() -> None:
    """Ensure all tables exist. Safe to call multiple times, even across threads."""
    global _tables_initialized
    with _tables_lock:
        if not _tables_initialized:
            models_init_db()
            _tables_initialized = True
    logger.debug("Database tables and constraints verified.")


@contextmanager
def get_session():
    """
    Yield a brand‑new session and commit on success, rollback on failure.
    The session is always closed at the end.
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Sanitization helpers (stricter numeric conversion)
# ---------------------------------------------------------------------------
def _truncate_string(value: str, max_length: int = 2000) -> str:
    if value and len(value) > max_length:
        return value[:max_length]
    return value


def _safe_float(value: Any) -> float | None:
    """Convert to float only if value is a true int or float (not bool)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        # Only pure numeric strings allowed, no suffixes like 's'
        clean = value.strip()
        try:
            return float(clean)
        except ValueError:
            return None
    return None


def _safe_int(value: Any) -> int | None:
    """Convert to int only if value is a true int (not bool)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        clean = value.strip()
        try:
            return int(clean)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# Persistence functions
# ---------------------------------------------------------------------------
def save_scan(
    findings: list[dict[str, Any]],
    ai_summary: dict[str, Any] | None = None,
) -> int | None:
    """
    Persist a scan and its findings atomically using ORM validation.

    Returns scan_id (int) on success, None on failure.
    """
    init_db()

    try:
        with get_session() as session:
            exec_time = _safe_float(
                ai_summary.get("execution_time") if ai_summary else None
            )

            new_scan = Scan(
                timestamp=datetime.now(UTC),
                risk_score=ai_summary.get("risk_score") if ai_summary else None,
                hardware_profile=ai_summary.get("hardware_profile") if ai_summary else None,
                execution_time=exec_time,
                ai_summary_json=json.dumps(ai_summary) if ai_summary else None,
            )
            session.add(new_scan)
            session.flush()  # to get scan.id

            # Convert and validate all findings, then add via ORM
            valid_objects = []
            for f in findings:
                try:
                    valid = FindingSchema(**f)
                    valid_objects.append(Finding(
                        scan_id=new_scan.id,
                        tool=_truncate_string(valid.tool),
                        rule_id=_truncate_string(valid.rule_id or valid.id, 500),
                        severity=valid.severity,
                        target=_truncate_string(valid.target, 1000),
                        title=_truncate_string(valid.title, 500),
                        description=_truncate_string(valid.description or "", 2000),
                        line=_safe_int(valid.line),
                        dynamic_risk_score=valid.dynamic_risk_score,
                    ))
                except ValidationError as e:
                    logger.warning(f"Skipping invalid finding: {e}")
                    continue

            if valid_objects:
                session.add_all(valid_objects)

            logger.success(f"Scan {new_scan.id} saved with {len(valid_objects)} findings.")
            return int(new_scan.id)

    except SQLAlchemyError as e:
        logger.error(f"Database error while saving scan: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error while saving scan: {e}")
        return None


def update_scan_ai_summary(scan_id: int, ai_summary: dict[str, Any]) -> bool:
    """
    Update an existing scan with AI analysis results.

    Returns True on success.
    """
    init_db()
    try:
        with get_session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                logger.error(f"Scan {scan_id} not found for AI summary update.")
                return False

            scan.risk_score = ai_summary.get("risk_score", scan.risk_score)
            scan.hardware_profile = ai_summary.get("hardware_profile", scan.hardware_profile)
            scan.execution_time = _safe_float(ai_summary.get("execution_time"))
            scan.ai_summary_json = json.dumps(ai_summary)

            logger.success(f"AI summary updated for scan {scan_id}")
            return True
    except Exception as e:
        logger.error(f"Failed to update AI summary for scan {scan_id}: {e}")
        return False


# ---------------------------------------------------------------------------
# Query functions
# ---------------------------------------------------------------------------
def get_all_scans() -> list[dict[str, Any]]:
    with get_session() as session:
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
    with get_session() as session:
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
            "ai_summary_json": scan.ai_summary_json,   # ← now included
            "findings": findings_list,
        }


def get_findings_paginated(page: int = 1, per_page: int = 50) -> dict[str, Any]:
    per_page = max(1, min(per_page, 100))
    page = max(1, page)

    with get_session() as session:
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
    """
    Compare two scans and return added / removed findings using a set‑based
    SQL approach that is memory‑efficient.
    """
    with get_session() as session:
        # Subquery for findings of each scan
        f1 = session.query(Finding.rule_id).filter(Finding.scan_id == scan_id1).subquery()
        f2 = session.query(Finding.rule_id).filter(Finding.scan_id == scan_id2).subquery()

        # Added: in f2 but not in f1
        added_rows = session.query(Finding).filter(
            Finding.scan_id == scan_id2,
            Finding.rule_id.notin_(f1)
        ).all()
        # Removed: in f1 but not in f2
        removed_rows = session.query(Finding).filter(
            Finding.scan_id == scan_id1,
            Finding.rule_id.notin_(f2)
        ).all()

        added = [
            {"tool": f.tool, "id": f.rule_id, "severity": f.severity, "target": f.target, "title": f.title}
            for f in added_rows
        ]
        removed = [
            {"tool": f.tool, "id": f.rule_id, "severity": f.severity, "target": f.target, "title": f.title}
            for f in removed_rows
        ]

        return {"scan_id1": scan_id1, "scan_id2": scan_id2, "added": added, "removed": removed}
