import json
import os

from flask import Blueprint, jsonify

attack_paths_bp = Blueprint('attack_paths', __name__)

AI_SUMMARY_FILE = os.environ.get('AI_SUMMARY_FILE', 'findings_ai_summary.json')
FINDINGS_FILE = os.environ.get('FINDINGS_FILE', 'findings.json')


def load_findings():
    if not os.path.exists(FINDINGS_FILE):
        return []
    with open(FINDINGS_FILE) as f:
        return json.load(f)


@attack_paths_bp.route('/attack-paths')
def api_attack_paths():
    """
    Return attack‑path graph data only from the cached AI summary.
    The CLI must be run with --analyze to generate the summary file.
    No live Ollama call is ever made here – keeps the API fast and reliable.
    """
    # If no cached summary exists, return empty graph immediately.
    if not os.path.exists(AI_SUMMARY_FILE):
        return jsonify({"attack_paths": [], "nodes": [], "links": []})

    with open(AI_SUMMARY_FILE) as f:
        analysis = json.load(f)

    attack_paths = analysis.get("attack_paths", [])
    findings = load_findings()

    nodes = []
    links = []
    node_ids = set()

    for path in attack_paths:
        involved = path.get("involved_findings", [])
        for fid in involved:
            if fid not in node_ids:
                finding = next((f for f in findings if f.get("id") == fid), None)
                nodes.append({
                    "id": fid,
                    "label": fid,
                    "severity": finding.get("severity", "UNKNOWN") if finding else "UNKNOWN",
                    "title": finding.get("title", "")[:50] if finding else ""
                })
                node_ids.add(fid)
        for i in range(len(involved) - 1):
            links.append({
                "source": involved[i],
                "target": involved[i + 1],
                "description": path.get("description", "")
            })

    return jsonify({"attack_paths": attack_paths, "nodes": nodes, "links": links})
