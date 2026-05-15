from flask import Blueprint, jsonify
import json
import os

attack_paths_bp = Blueprint('attack_paths', __name__)

@attack_paths_bp.route('/api/attack-paths')
def api_attack_paths():
    findings_file = os.environ.get('FINDINGS_FILE', 'findings.json')
    if not os.path.exists(findings_file):
        return jsonify({"attack_paths": [], "nodes": [], "links": []})
    with open(findings_file) as f:
        findings = json.load(f)
    try:
        from devsecops_radar.core.analyzer import OllamaAnalyzer
        analyzer = OllamaAnalyzer()
        analysis = analyzer.analyze(findings)
        attack_paths = analysis.get("attack_paths", [])
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
                    "target": involved[i+1],
                    "description": path.get("description", "")
                })
        return jsonify({"attack_paths": attack_paths, "nodes": nodes, "links": links})
    except Exception as e:
        return jsonify({"error": f"AI analysis unavailable: {str(e)}", "attack_paths": [], "nodes": [], "links": []})