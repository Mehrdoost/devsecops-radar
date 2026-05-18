from flask import Blueprint, request, jsonify

sentry_bp = Blueprint('sentry', __name__)

LIVE_FINDINGS = []

@sentry_bp.route('/api/scan-result', methods=['POST'])
def receive_scan():
    data = request.get_json(force=True)
    LIVE_FINDINGS.append(data)
    return jsonify({"status": "received"})

@sentry_bp.route('/api/live-findings')
def get_live():
    return jsonify(LIVE_FINDINGS)