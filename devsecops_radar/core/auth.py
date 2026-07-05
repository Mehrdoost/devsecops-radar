# devsecops_radar/core/auth.py
"""
Authentication and authorization decorators for Flask endpoints.
Provides JWT and API‑Key based protection with thread‑safe rate limiting.
Automatically relaxes limits for localhost in development environments.
"""

from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any

import jwt
from flask import jsonify, request
from loguru import logger

from devsecops_radar.core.settings import settings

# ---------------------------------------------------------------------------
# Thread‑safe rate limiter
# ---------------------------------------------------------------------------
_RATE_LIMIT_WINDOW = 60           # seconds
_MAX_ATTEMPTS_PER_WINDOW = 50     # per IP (raised from 20 to avoid false positives)

_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_lock = threading.Lock()


def _get_remote_ip() -> str:
    """Return the client IP as set by Flask/Werkzeug (after ProxyFix)."""
    return request.remote_addr or "127.0.0.1"


def _is_localhost(ip: str) -> bool:
    """Check if the IP belongs to the loopback interface."""
    return ip in ("127.0.0.1", "::1", "localhost")


def _check_rate_limit(ip: str) -> bool:
    """
    Return True if the IP is allowed to proceed. Thread‑safe.

    For localhost a much higher limit is used so that the dashboard
    can make many concurrent API calls without hitting 429 errors.
    """
    now = time.time()
    with _rate_lock:
        timestamps = _rate_store.get(ip, [])
        # Remove old entries
        timestamps = [t for t in timestamps if now - t < _RATE_LIMIT_WINDOW]

        # relaxed limit for local development
        if _is_localhost(ip):
            max_attempts = 200
        else:
            max_attempts = _MAX_ATTEMPTS_PER_WINDOW

        if len(timestamps) >= max_attempts:
            _rate_store[ip] = timestamps
            return False
        timestamps.append(now)
        _rate_store[ip] = timestamps
        return True


def _cleanup_rate_store() -> None:
    """Remove expired IP entries. Must be called periodically."""
    now = time.time()
    with _rate_lock:
        for ip in list(_rate_store.keys()):
            _rate_store[ip] = [t for t in _rate_store[ip] if now - t < _RATE_LIMIT_WINDOW]
            if not _rate_store[ip]:
                del _rate_store[ip]


def start_cleanup_thread(interval: float = 120.0) -> threading.Thread:
    """Start a background thread that periodically cleans the rate‑limit store."""
    def _loop():
        _cleanup_rate_store()
        threading.Timer(interval, _loop).start()
    t = threading.Timer(interval, _loop)
    t.daemon = True
    t.start()
    return t


# ---------------------------------------------------------------------------
# Token creation and validation
# ---------------------------------------------------------------------------
def create_token(user: str = "admin") -> str:
    try:
        now = datetime.now(UTC)
        payload = {
            "user": user,
            "exp": now + timedelta(hours=1),
            "iat": now,
        }
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")
        logger.info(f"JWT token created for user '{user}' (expires in 1 hour).")
        return token
    except Exception as e:
        logger.error(f"JWT generation failed: {str(e)}")
        raise RuntimeError("Could not generate authentication token.") from e


def _extract_token_from_header() -> str | None:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    parts = auth_header.split(" ")
    if len(parts) < 2:
        return None
    return parts[-1]


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------
def login_required(f: Callable) -> Callable:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        ip = _get_remote_ip()
        if not _check_rate_limit(ip):
            logger.warning(f"Rate limit exceeded for {ip} on JWT endpoint.")
            return jsonify({"error": "Too many requests. Please slow down."}), 429

        token = _extract_token_from_header()
        if not token:
            return jsonify({"error": "Missing or invalid Authorization header. Expected Bearer token."}), 401

        payload = None
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            logger.warning(f"Expired JWT token used from IP {ip}")
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            logger.warning(f"Invalid JWT token used from IP {ip}")
            return jsonify({"error": "Invalid token."}), 401
        except Exception as e:
            logger.error(f"Unexpected error during JWT validation: {str(e)}")
            return jsonify({"error": "Authentication failed."}), 500

        request.user = payload.get("user")        # type: ignore[attr-defined]
        logger.info(f"JWT authentication successful for user '{payload.get('user')}' from IP {ip}")
        return f(*args, **kwargs)
    return decorated


def require_api_key(f: Callable) -> Callable:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        ip = _get_remote_ip()
        if not _check_rate_limit(ip):
            logger.warning(f"Rate limit exceeded for {ip} on API Key endpoint.")
            return jsonify({"error": "Too many requests. Please slow down."}), 429

        api_key = request.headers.get("X-API-Key")
        expected_key = settings.PIPELINE_API_KEY

        if not api_key:
            return jsonify({"error": "Missing API key. Provide X-API-Key header."}), 401

        api_key = api_key.strip()
        if not hmac.compare_digest(api_key, expected_key):
            logger.warning(f"Invalid API key attempt from IP: {ip}")
            return jsonify({"error": "Invalid API key."}), 401

        request.user = "api_key_user"               # type: ignore[attr-defined]
        logger.info(f"API key authentication successful from IP {ip}")
        return f(*args, **kwargs)
    return decorated


def require_any_auth(f: Callable) -> Callable:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        ip = _get_remote_ip()
        # Rate limit applies regardless of authentication method
        if not _check_rate_limit(ip):
            logger.warning(f"Rate limit exceeded for {ip} on combined auth endpoint.")
            return jsonify({"error": "Too many requests. Please slow down."}), 429

        # 1. Try API Key
        api_key = request.headers.get("X-API-Key")
        if api_key:
            api_key = api_key.strip()
            if hmac.compare_digest(api_key, settings.PIPELINE_API_KEY):
                request.user = "api_key_user"           # type: ignore[attr-defined]
                logger.info(f"API key authentication successful from IP {ip}")
                return f(*args, **kwargs)

        # 2. Try JWT
        token = _extract_token_from_header()
        if token:
            payload = None
            try:
                payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                logger.warning(f"Expired JWT token used from IP {ip}")
            except jwt.InvalidTokenError:
                logger.warning(f"Invalid JWT token used from IP {ip}")
            except Exception as e:
                logger.error(f"Unexpected error during JWT validation: {str(e)}")
            else:
                request.user = payload.get("user")        # type: ignore[attr-defined]
                logger.info(f"JWT authentication successful for user '{payload.get('user')}' from IP {ip}")
                return f(*args, **kwargs)

        # 3. Both methods failed
        return jsonify({
            "error": "Authentication required. Provide a valid API key (X-API-Key) or Bearer token."
        }), 401
    return decorated


def verify_api_key(provided_key: str) -> bool:
    if not provided_key:
        return False
    provided_key = provided_key.strip()
    result = hmac.compare_digest(provided_key, settings.PIPELINE_API_KEY)
    if not result:
        logger.warning("Invalid API key provided to verify_api_key.")
    else:
        logger.info("API key verified successfully via direct call.")
    return result
