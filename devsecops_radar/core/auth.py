import hmac
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any

import jwt
from flask import jsonify, request
from loguru import logger

from devsecops_radar.core.settings import settings

# ---------------------------------------------------------------------------
# Simple in-memory rate limiter (thread‑safe) – only counts failed attempts
# ---------------------------------------------------------------------------
_rate_limit_store: dict[str, list[float]] = {}
_rate_limit_lock = threading.Lock()

# Limits are for *failed* attempts per window
_API_KEY_MAX_FAILURES = 20        # per minute
_JWT_MAX_FAILURES = 10
_WINDOW_SECONDS = 60


def _record_failed_attempt(limit: int) -> bool:
    """
    Record a failed authentication attempt from the current IP.
    Returns True if the failure limit has been exceeded (should be blocked),
    otherwise False (allowed but failed).
    """
    ip = request.remote_addr or "unknown"
    now = time.time()
    with _rate_limit_lock:
        timestamps = _rate_limit_store.get(ip, [])
        # Remove expired entries
        timestamps = [t for t in timestamps if now - t < _WINDOW_SECONDS]
        # Check limit before adding new failure
        if len(timestamps) >= limit:
            _rate_limit_store[ip] = timestamps
            return True   # blocked
        # Record this failure
        timestamps.append(now)
        _rate_limit_store[ip] = timestamps
        return False


def _extract_token_from_header() -> str | None:
    """Safely extract Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    parts = auth_header.split(" ")
    if len(parts) < 2:
        return None
    return parts[-1]   # take the last part to handle extra spaces


# ---------------------------------------------------------------------------
# Token creation and validation (unchanged)
# ---------------------------------------------------------------------------
def create_token(user: str = "admin") -> str:
    """Generate a secure JWT token for the authenticated user."""
    try:
        now = datetime.now(UTC)
        payload = {
            "user": user,
            "exp": now + timedelta(hours=1),
            "iat": now,
        }
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")
        return token
    except Exception as e:
        logger.error(f"JWT generation failed: {str(e)}")
        raise RuntimeError("Could not generate authentication token.") from e


# ---------------------------------------------------------------------------
# Authentication decorators – rate limiting only on failures
# ---------------------------------------------------------------------------
def login_required(f: Callable) -> Callable:
    """
    Decorator to protect API endpoints using JWT Bearer token.
    Failed token attempts are rate‑limited to prevent brute force.
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        token = _extract_token_from_header()
        if not token:
            if _record_failed_attempt(_JWT_MAX_FAILURES):
                return jsonify({"error": "Too many login failures. Please slow down."}), 429
            return jsonify(
                {"error": "Missing or invalid Authorization header. Expected Bearer token."}
            ), 401

        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
            request.user = payload.get("user")
        except jwt.ExpiredSignatureError:
            # token expiry counts as a failure
            if _record_failed_attempt(_JWT_MAX_FAILURES):
                return jsonify({"error": "Too many login failures. Please slow down."}), 429
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            if _record_failed_attempt(_JWT_MAX_FAILURES):
                return jsonify({"error": "Too many login failures. Please slow down."}), 429
            return jsonify({"error": "Invalid token."}), 401
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {str(e)}")
            return jsonify({"error": "Authentication failed."}), 500

        return f(*args, **kwargs)

    return decorated


def require_api_key(f: Callable) -> Callable:
    """
    Decorator to protect API endpoints using a simple API Key (X-API-Key header).
    Failed attempts are rate‑limited.
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        api_key = request.headers.get("X-API-Key")
        expected_key = settings.PIPELINE_API_KEY

        if not api_key:
            if _record_failed_attempt(_API_KEY_MAX_FAILURES):
                return jsonify({"error": "Too many API key failures. Please slow down."}), 429
            return jsonify({"error": "Missing API key. Provide X-API-Key header."}), 401

        api_key = api_key.strip()
        if not hmac.compare_digest(api_key, expected_key):
            logger.warning(f"Invalid API key attempt from IP: {request.remote_addr}")
            if _record_failed_attempt(_API_KEY_MAX_FAILURES):
                return jsonify({"error": "Too many API key failures. Please slow down."}), 429
            return jsonify({"error": "Invalid API key."}), 401

        return f(*args, **kwargs)

    return decorated


def require_any_auth(f: Callable) -> Callable:
    """
    Decorator that accepts either a valid API key (X-API-Key header)
    or a valid JWT token (Authorization: Bearer <token>).
    Rate limiting is applied only on failed attempts.
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        # 1. Try API key first
        api_key = request.headers.get("X-API-Key")
        if api_key:
            api_key = api_key.strip()
            if hmac.compare_digest(api_key, settings.PIPELINE_API_KEY):
                return f(*args, **kwargs)
            # API key invalid – count as API key failure
            logger.warning(f"Invalid API key attempt from IP: {request.remote_addr}")
            if _record_failed_attempt(_API_KEY_MAX_FAILURES):
                return jsonify({"error": "Too many API key failures. Please slow down."}), 429
            return jsonify({"error": "Invalid API key."}), 401

        # 2. Fall back to JWT
        token = _extract_token_from_header()
        if not token:
            if _record_failed_attempt(_JWT_MAX_FAILURES):
                return jsonify({"error": "Too many authentication failures. Please slow down."}), 429
            return jsonify(
                {"error": "Missing authentication. Provide X-API-Key or Bearer token."}
            ), 401

        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
            request.user = payload.get("user")
        except jwt.ExpiredSignatureError:
            if _record_failed_attempt(_JWT_MAX_FAILURES):
                return jsonify({"error": "Too many authentication failures. Please slow down."}), 429
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            if _record_failed_attempt(_JWT_MAX_FAILURES):
                return jsonify({"error": "Too many authentication failures. Please slow down."}), 429
            return jsonify({"error": "Invalid token."}), 401
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {str(e)}")
            return jsonify({"error": "Authentication failed."}), 500

        return f(*args, **kwargs)

    return decorated


def verify_api_key(provided_key: str) -> bool:
    """Constant-time comparison of a provided API key against the system key."""
    if not provided_key:
        return False
    provided_key = provided_key.strip()
    result = hmac.compare_digest(provided_key, settings.PIPELINE_API_KEY)
    if not result:
        logger.warning("Invalid API key provided to verify_api_key.")
    return result