# devsecops_radar/web/attack_paths/routes.py
import json
import os
from pathlib import Path

from flask import Blueprint, jsonify

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.path_security import safe_read_open

attack_paths_bp = Blueprint("attack_paths", __name__)

_ALLOWED_DATA_DIR = Path.cwd().resolve()
AI_SUMMARY_FILE = os.environ.get("AI_SUMMARY_FILE", "findings_ai_summary.json")
FINDINGS_FILE = os.environ.get("FINDINGS_FILE", "findings.json")


def _load_findings() -> list[dict]:
    try:
        with safe_read_open(FINDINGS_FILE, base_dir=_ALLOWED_DATA_DIR) as f:
            return json.load(f)
    except (ValueError, FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
        return []


@attack_paths_bp.route("/attack-paths")
@require_any_auth
def api_attack_paths():
    findings = _load_findings()
    if not findings:
        return jsonify({"attack_paths": [], "nodes": [], "links": []})

    # Load AI analysis summary safely
    analysis = {}
    try:
        with safe_read_open(AI_SUMMARY_FILE, base_dir=_ALLOWED_DATA_DIR) as f:
            analysis = json.load(f)
    except (ValueError, FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
        pass  # it's okay if there's no AI summary

    attack_paths = analysis.get("attack_paths", [])
    findings_by_id = {f.get("id"): f for f in findings}

    nodes = []
    links = []
    node_ids = set()

    # Build graph from AI‑provided involved_findings (now present in AttackPath model)
    for path in attack_paths:
        involved = path.get("involved_findings", [])
        if involved:
            for fid in involved:
                if fid not in node_ids:
                    finding = findings_by_id.get(fid)
                    nodes.append({
                        "id": fid,
                        "label": fid,
                        "severity": finding.get("severity", "UNKNOWN") if finding else "UNKNOWN",
                        "title": (finding.get("title", "")[:50] if finding else ""),
                    })
                    node_ids.add(fid)
            for i in range(len(involved) - 1):
                links.append({
                    "source": involved[i],
                    "target": involved[i + 1],
                    "description": path.get("description", ""),
                })

    return jsonify({"attack_paths": attack_paths, "nodes": nodes, "links": links})
