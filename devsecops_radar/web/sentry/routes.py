# devsecops_radar/web/sentry/routes.py
"""
Live Sentry Feed – receives scan results from CI/CD systems,
validates them, stores them in the database (with deduplication),
and keeps a thread‑safe in‑memory buffer for instant dashboard updates.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from html import escape as html_escape

from flask import Blueprint, jsonify, request
from loguru import logger
from pydantic import ValidationError

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.database import SessionLocal, save_scan
from devsecops_radar.core.models import Finding, FindingSchema, Scan
from devsecops_radar.core.reporting import redact_sensitive

sentry_bp = Blueprint("sentry", __name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_MAX_LIVE_FINDINGS = 1000
_MAX_PAYLOAD_SIZE = 1 * 1024 * 1024
_TTL_SECONDS = int(os.environ.get("LIVE_FINDINGS_TTL", "900"))

# Each entry: (sanitized_finding_dict, arrival_timestamp)
_LIVE_BUFFER: deque[tuple[dict, float]] = deque(maxlen=_MAX_LIVE_FINDINGS)
_LIVE_LOCK = threading.Lock()

# Optional webhook secret
_WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "").encode("utf-8") if os.environ.get("WEBHOOK_SECRET") else None

# Deduplication window (seconds) – don't store the same finding again within this period
_DEDUP_WINDOW = int(os.environ.get("SENTRY_DEDUP_WINDOW", "86400"))  # 24 hours

# Rate limiting for /scan-result
_SCAN_RATE_WINDOW = 60
_SCAN_MAX_PER_WINDOW = 30
_scan_rate_store: dict[str, list[float]] = {}
_scan_rate_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Buffer management
# ---------------------------------------------------------------------------
def _prune_expired(now: float | None = None) -> None:
    if now is None:
        now = time.time()
    cutoff = now - _TTL_SECONDS
    while _LIVE_BUFFER and _LIVE_BUFFER[0][1] < cutoff:
        _LIVE_BUFFER.popleft()


def _sanitize_finding(finding: dict) -> dict:
    clean: dict = {}
    for key, value in finding.items():
        if isinstance(value, str):
            clean[key] = html_escape(redact_sensitive(value))
        elif isinstance(value, dict):
            clean[key] = _sanitize_finding(value)
        elif isinstance(value, list):
            clean[key] = [
                _sanitize_finding(item) if isinstance(item, dict)
                else html_escape(redact_sensitive(item)) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            clean[key] = value
    return clean


def get_live_snapshot(limit: int = 100) -> list[dict]:
    with _LIVE_LOCK:
        _prune_expired()
        # Return the most recent items (already sanitised at insertion)
        items = [item[0] for item in _LIVE_BUFFER]
        return items[-limit:] if limit > 0 else items


# ---------------------------------------------------------------------------
# Webhook signature verification
# ---------------------------------------------------------------------------
def _verify_webhook_signature(payload_body: bytes, signature_header: str | None) -> bool:
    if _WEBHOOK_SECRET is None:
        return True
    if not signature_header:
        logger.warning("Missing webhook signature header.")
        return False
    try:
        algorithm, signature = signature_header.split("=", 1)
        if algorithm != "sha256":
            logger.warning(f"Unsupported webhook signature algorithm: {algorithm}")
            return False
        expected = hmac.new(_WEBHOOK_SECRET, payload_body, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, signature):
            return True
        logger.warning("Webhook signature mismatch.")
        return False
    except Exception as e:
        logger.error(f"Webhook signature verification error: {e}")
        return False


# ---------------------------------------------------------------------------
# Deduplication helper
# ---------------------------------------------------------------------------
def _is_duplicate(finding: dict) -> bool:
    """Return True if a finding with the same rule_id, tool, and target
    was saved within the deduplication window."""
    rule_id = finding.get("rule_id") or finding.get("id")
    tool = finding.get("tool")
    target = finding.get("target")

    if not rule_id or not tool:
        return False

    session = SessionLocal()
    try:
        cutoff = datetime.now(UTC) - timedelta(seconds=_DEDUP_WINDOW)
        exists = session.query(Finding).filter(
            Finding.rule_id == rule_id,
            Finding.tool == tool,
            Finding.target == target,
            Finding.scan.has(Scan.timestamp >= cutoff),
        ).first()
        return exists is not None
    except Exception as e:
        logger.error(f"Deduplication check failed: {e}")
        return False
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Rate limiting for scan submission
# ---------------------------------------------------------------------------
def _check_scan_rate_limit(ip: str) -> bool:
    now = time.time()
    with _scan_rate_lock:
        timestamps = _scan_rate_store.get(ip, [])
        timestamps = [t for t in timestamps if now - t < _SCAN_RATE_WINDOW]
        if len(timestamps) >= _SCAN_MAX_PER_WINDOW:
            _scan_rate_store[ip] = timestamps
            return False
        timestamps.append(now)
        _scan_rate_store[ip] = timestamps
        return True


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@sentry_bp.route("/scan-result", methods=["POST"])
@require_any_auth
def receive_scan():
    ip = request.remote_addr or "127.0.0.1"
    if not _check_scan_rate_limit(ip):
        return jsonify({"error": "Too many scan submissions. Please slow down."}), 429

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    if request.content_length and request.content_length > _MAX_PAYLOAD_SIZE:
        return jsonify({"error": "Payload too large"}), 413

    raw_body = request.get_data()
    signature_header = request.headers.get("X-Pipeline-Signature")
    if not _verify_webhook_signature(raw_body, signature_header):
        return jsonify({"error": "Invalid webhook signature"}), 401

    try:
        data = request.get_json(force=False, silent=False)
    except Exception:
        return jsonify({"error": "Malformed JSON"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    try:
        valid_finding = FindingSchema(**data)
    except ValidationError as e:
        logger.warning(f"Invalid finding rejected: {e}")
        return jsonify({"error": "Invalid finding format", "details": str(e)}), 422

    finding_dict = valid_finding.model_dump()

    # Check for duplicates
    if _is_duplicate(finding_dict):
        logger.info(f"Duplicate finding ignored: {finding_dict.get('id', 'N/A')}")
        return jsonify({"status": "duplicate"})

    # Save to database
    try:
        save_scan([finding_dict])
    except Exception as e:
        logger.error(f"Failed to save live finding to database: {e}")
        return jsonify({"error": "Failed to store finding"}), 500

    # Sanitise and add to buffer
    clean = _sanitize_finding(finding_dict)
    now = time.time()
    with _LIVE_LOCK:
        _prune_expired(now)
        _LIVE_BUFFER.append((clean, now))
        logger.info(f"Live finding accepted: {finding_dict.get('id', 'N/A')} "
                    f"(buffer size: {len(_LIVE_BUFFER)})")

    return jsonify({"status": "received"})


@sentry_bp.route("/live-findings", methods=["GET"])
@require_any_auth
def get_live():
    limit = request.args.get("limit", 100, type=int)
    return jsonify(get_live_snapshot(limit=limit))
