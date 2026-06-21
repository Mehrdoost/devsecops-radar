# devsecops_radar/web/summary/routes.py
import json
import os
from pathlib import Path

from flask import Blueprint, jsonify

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.database import get_scan_by_id
from devsecops_radar.core.path_security import safe_read_open

summary_bp = Blueprint("summary", __name__)

_ALLOWED_DATA_DIR = Path.cwd().resolve()
AI_SUMMARY_FILE = os.environ.get("AI_SUMMARY_FILE", "findings_ai_summary.json")


@summary_bp.route("/summary")
@require_any_auth
def api_summary():
    try:
        with safe_read_open(AI_SUMMARY_FILE, base_dir=_ALLOWED_DATA_DIR) as f:
            return jsonify(json.load(f))
    except (ValueError, FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
        return jsonify({})


@summary_bp.route("/badge/<int:scan_id>.svg")
def security_badge(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Scan not found", 404
    critical = sum(1 for f in scan["findings"] if f["severity"] == "CRITICAL")
    if critical == 0:
        color = "green"
        text = "Secure"
    elif critical <= 3:
        color = "yellow"
        text = "Warning"
    else:
        color = "red"
        text = "Vulnerable"
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="120" height="20">
      <rect width="120" height="20" fill="{color}" rx="3"/>
      <text x="60" y="14" fill="white" font-size="10" text-anchor="middle" font-family="Arial">{text}</text>
    </svg>'''
    return svg, 200, {"Content-Type": "image/svg+xml"}
