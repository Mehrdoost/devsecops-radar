import json
import os
from pathlib import Path

from flask import Blueprint, jsonify

from devsecops_radar.core.auth import require_any_auth

attack_paths_bp = Blueprint("attack_paths", __name__)

_ALLOWED_DATA_DIR = Path.cwd().resolve()
AI_SUMMARY_FILE = os.environ.get("AI_SUMMARY_FILE", "findings_ai_summary.json")
FINDINGS_FILE = os.environ.get("FINDINGS_FILE", "findings.json")

def _safe_data_path(filename: str) -> Path | None:
    file_path = (_ALLOWED_DATA_DIR / filename).resolve()
    try:
        if file_path.is_relative_to(_ALLOWED_DATA_DIR):
            return file_path
    except ValueError:
        pass
    return None

def _load_findings() -> list[dict]:
    safe_path = _safe_data_path(FINDINGS_FILE)
    if not safe_path or not safe_path.exists():
        return []
    with open(safe_path, encoding="utf-8") as f:
        return json.load(f)

@attack_paths_bp.route("/attack-paths")
@require_any_auth
def api_attack_paths():
    safe_summary_path = _safe_data_path(AI_SUMMARY_FILE)
    if not safe_summary_path or not safe_summary_path.exists():
        return jsonify({"attack_paths": [], "nodes": [], "links": []})

    with open(safe_summary_path, encoding="utf-8") as f:
        analysis = json.load(f)

    attack_paths = analysis.get("attack_paths", [])
    findings_list = _load_findings()
    findings_by_id = {f.get("id"): f for f in findings_list}

    nodes = []
    links = []
    node_ids = set()

    for path in attack_paths:
        involved = path.get("involved_findings", [])
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
