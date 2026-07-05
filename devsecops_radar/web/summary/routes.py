# devsecops_radar/web/summary/routes.py
"""
Executive summary and security badge API – powered by the database.
"""

from __future__ import annotations

import json
import time
from html import escape as html_escape
from typing import Any

from flask import Blueprint, jsonify

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.models import Finding, Scan, SessionLocal
from devsecops_radar.core.reporting import redact_sensitive

summary_bp = Blueprint("summary", __name__)

# Simple in‑memory cache for badge SVGs
_badge_cache: dict[int, tuple[str, float]] = {}
_BADGE_CACHE_TTL = 300  # 5 minutes


def _sanitize_ai_summary(ai_summary: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in ai_summary.items():
        if isinstance(value, str):
            sanitized[key] = html_escape(redact_sensitive(value))
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_ai_summary(value)
        elif isinstance(value, list):
            sanitized[key] = [
                _sanitize_ai_summary(item) if isinstance(item, dict)
                else html_escape(redact_sensitive(item)) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            sanitized[key] = value
    return sanitized


@summary_bp.route("/summary")
@require_any_auth
def api_summary():
    session = SessionLocal()
    try:
        scan = session.query(Scan).filter(
            Scan.ai_summary_json.isnot(None)
        ).order_by(Scan.id.desc()).first()

        if not scan:
            return jsonify({})

        try:
            ai_summary = json.loads(scan.ai_summary_json)
        except (json.JSONDecodeError, TypeError):
            return jsonify({})

        total_findings = session.query(Finding).filter(
            Finding.scan_id == scan.id
        ).count()
        critical_count = session.query(Finding).filter(
            Finding.scan_id == scan.id,
            Finding.severity == "CRITICAL",
        ).count()

        ai_summary["total_findings"] = total_findings
        ai_summary["critical_findings"] = critical_count

    finally:
        session.close()

    return jsonify(_sanitize_ai_summary(ai_summary))


@summary_bp.route("/badge/<int:scan_id>.svg")
def security_badge(scan_id):
    """Public endpoint – no authentication required (data is non‑sensitive)."""

    # Return cached SVG if fresh
    now = time.time()
    if scan_id in _badge_cache:
        svg_cached, timestamp = _badge_cache[scan_id]
        if (now - timestamp) < _BADGE_CACHE_TTL:
            return svg_cached, 200, {"Content-Type": "image/svg+xml"}

    session = SessionLocal()
    try:
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return "Scan not found", 404

        critical_count = session.query(Finding).filter(
            Finding.scan_id == scan_id,
            Finding.severity == "CRITICAL",
        ).count()
    finally:
        session.close()

    if critical_count == 0:
        color, text = "green", "Secure"
    elif critical_count <= 3:
        color, text = "yellow", "Warning"
    else:
        color, text = "red", "Vulnerable"

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="120" height="20">
      <rect width="120" height="20" fill="{color}" rx="3"/>
      <text x="60" y="14" fill="white" font-size="10" text-anchor="middle" font-family="Arial">{text}</text>
    </svg>'''

    # Update cache
    _badge_cache[scan_id] = (svg, now)

    return svg, 200, {"Content-Type": "image/svg+xml"}
