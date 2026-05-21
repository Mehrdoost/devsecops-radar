import json
import os

from flask import Blueprint, jsonify

summary_bp = Blueprint('summary', __name__)

AI_SUMMARY_FILE = os.environ.get('AI_SUMMARY_FILE', 'findings_ai_summary.json')

@summary_bp.route('/api/summary')
def api_summary():
    if os.path.exists(AI_SUMMARY_FILE):
        with open(AI_SUMMARY_FILE) as f:
            return jsonify(json.load(f))
    return jsonify({})

@summary_bp.route('/badge/<int:scan_id>.svg')
def security_badge(scan_id):
    from devsecops_radar.core.database import get_scan_by_id
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Scan not found", 404
    critical = sum(1 for f in scan['findings'] if f['severity'] == 'CRITICAL')
    if critical == 0:
        color = 'green'
        text = 'Secure'
    elif critical <= 3:
        color = 'yellow'
        text = 'Warning'
    else:
        color = 'red'
        text = 'Vulnerable'
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="120" height="20">
      <rect width="120" height="20" fill="{color}" rx="3"/>
      <text x="60" y="14" fill="white" font-size="10" text-anchor="middle" font-family="Arial">{text}</text>
    </svg>'''
    return svg, 200, {'Content-Type': 'image/svg+xml'}
