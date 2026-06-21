# devsecops_radar/web/sentry/routes.py
import threading
import time
from collections import deque

from flask import Blueprint, jsonify, request
from loguru import logger
from pydantic import ValidationError

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.models import FindingSchema

sentry_bp = Blueprint("sentry", __name__)

# ---------------------------------------------------------------------------
# Thread‑safe, TTL‑enabled in‑memory buffer for live findings
# ---------------------------------------------------------------------------
_MAX_LIVE_FINDINGS = 1000
_MAX_PAYLOAD_SIZE = 1 * 1024 * 1024         # bytes
_TTL_SECONDS = 300                          # 5 minutes

# Each entry: (finding_dict, arrival_timestamp)
_LIVE_BUFFER: deque[tuple[dict, float]] = deque(maxlen=_MAX_LIVE_FINDINGS)
_LIVE_LOCK = threading.Lock()


def _prune_expired(now: float | None = None) -> None:
    """Remove entries older than _TTL_SECONDS. Must be called while holding _LIVE_LOCK."""
    if now is None:
        now = time.time()
    cutoff = now - _TTL_SECONDS
    while _LIVE_BUFFER and _LIVE_BUFFER[0][1] < cutoff:
        _LIVE_BUFFER.popleft()


def get_live_snapshot() -> list[dict]:
    """
    Return a list of non‑expired live findings.
    This is the **only** supported way to access the buffer from other modules.
    """
    with _LIVE_LOCK:
        _prune_expired()
        return [item[0] for item in _LIVE_BUFFER]


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@sentry_bp.route("/scan-result", methods=["POST"])
@require_any_auth
def receive_scan():
    """Accept a single scan result from an external CI/CD system."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    if request.content_length and request.content_length > _MAX_PAYLOAD_SIZE:
        return jsonify({"error": "Payload too large"}), 413

    try:
        data = request.get_json(force=False, silent=False)
    except Exception:
        return jsonify({"error": "Malformed JSON"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    # Validate structure with Pydantic
    try:
        FindingSchema(**data)
    except ValidationError as e:
        logger.warning(f"Invalid finding rejected: {e}")
        return jsonify({"error": "Invalid finding format", "details": str(e)}), 422

    now = time.time()
    with _LIVE_LOCK:
        _prune_expired(now)
        _LIVE_BUFFER.append((data, now))
        logger.info(f"Live finding accepted: {data.get('id', 'N/A')} "
                    f"(buffer size: {len(_LIVE_BUFFER)})")

    return jsonify({"status": "received"})


@sentry_bp.route("/live-findings", methods=["GET"])
@require_any_auth
def get_live():
    """Return the current buffer of live findings (non‑expired)."""
    return jsonify(get_live_snapshot())
