import json
import os
from pathlib import Path

from flask import Blueprint, jsonify

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.database import get_scan_by_id

summary_bp = Blueprint("summary", __name__)

_ALLOWED_DATA_DIR = Path.cwd().resolve()
AI_SUMMARY_FILE = os.environ.get("AI_SUMMARY_FILE", "findings_ai_summary.json")

def _safe_data_path(filename: str) -> Path | None:
    file_path = (_ALLOWED_DATA_DIR / filename).resolve()
    try:
        if file_path.is_relative_to(_ALLOWED_DATA_DIR):
            return file_path
    except ValueError:
        pass
    return None

@summary_bp.route("/summary")
@require_any_auth
def api_summary():
    safe_path = _safe_data_path(AI_SUMMARY_FILE)
    if safe_path and safe_path.exists():
        with open(safe_path, encoding="utf-8") as f:
            return jsonify(json.load(f))
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
