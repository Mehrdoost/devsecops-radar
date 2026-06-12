import threading

from flask import Blueprint, jsonify, request
from loguru import logger
from pydantic import ValidationError

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.models import FindingSchema

sentry_bp = Blueprint("sentry", __name__)

# ---------------------------------------------------------------------------
# Secure in‑memory buffer for live findings
# ---------------------------------------------------------------------------
_LIVE_FINDINGS: list[dict] = []
_LIVE_LOCK = threading.Lock()
_MAX_LIVE_FINDINGS = 1000
_MAX_PAYLOAD_SIZE = 1 * 1024 * 1024  # bytes (redundant with Flask global, kept explicit)


@sentry_bp.route("/scan-result", methods=["POST"])
@require_any_auth
def receive_scan():
    """Accept a single scan result from an external CI/CD system."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    # Enforce a reasonable payload size (Flask global limit is 1 MB, but double‑check)
    if request.content_length and request.content_length > _MAX_PAYLOAD_SIZE:
        return jsonify({"error": "Payload too large"}), 413

    try:
        data = request.get_json(force=False, silent=False)
    except Exception:
        return jsonify({"error": "Malformed JSON"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    # Validate structure with Pydantic (but we allow partial – we store raw dict)
    try:
        FindingSchema(**data)
    except ValidationError as e:
        logger.warning(f"Invalid finding rejected: {e}")
        return jsonify({"error": "Invalid finding format", "details": str(e)}), 422

    # Add to buffer safely
    with _LIVE_LOCK:
        _LIVE_FINDINGS.append(data)
        # Trim oldest entries if exceeding limit
        while len(_LIVE_FINDINGS) > _MAX_LIVE_FINDINGS:
            _LIVE_FINDINGS.pop(0)

    return jsonify({"status": "received"})


@sentry_bp.route("/live-findings", methods=["GET"])
@require_any_auth
def get_live():
    """Return the current buffer of live findings."""
    with _LIVE_LOCK:
        # Return a shallow copy to avoid mutation during iteration
        return jsonify(list(_LIVE_FINDINGS))