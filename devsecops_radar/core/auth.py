# devsecops_radar/core/auth.py
import hmac
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any

import jwt
from flask import jsonify, request
from loguru import logger

from devsecops_radar.core.settings import settings


# ---------------------------------------------------------------------------
# Token creation and validation
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
        logger.info(f"JWT token created for user '{user}' (expires in 1 hour).")
        return token
    except Exception as e:
        logger.error(f"JWT generation failed: {str(e)}")
        raise RuntimeError("Could not generate authentication token.") from e


def _extract_token_from_header() -> str | None:
    """Safely extract Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    parts = auth_header.split(" ")
    if len(parts) < 2:
        return None
    return parts[-1]


# ---------------------------------------------------------------------------
# Authentication decorators (now with audit trail)
# ---------------------------------------------------------------------------
def login_required(f: Callable) -> Callable:
    """
    Decorator to protect API endpoints using JWT Bearer token.
    Successful authentications are logged for audit purposes.
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        token = _extract_token_from_header()
        if not token:
            return jsonify({"error": "Missing or invalid Authorization header. Expected Bearer token."}), 401

        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
            request.user = payload.get("user")        # type: ignore[attr-defined]
            logger.info(
                f"JWT authentication successful for user '{payload.get('user')}' "
                f"from IP {request.remote_addr}"
            )
        except jwt.ExpiredSignatureError:
            logger.warning(f"Expired JWT token used from IP {request.remote_addr}")
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            logger.warning(f"Invalid JWT token used from IP {request.remote_addr}")
            return jsonify({"error": "Invalid token."}), 401
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {str(e)}")
            return jsonify({"error": "Authentication failed."}), 500

        return f(*args, **kwargs)

    return decorated


def require_api_key(f: Callable) -> Callable:
    """
    Decorator to protect API endpoints using a simple API Key (X-API-Key header).
    Successful authentications are logged for audit purposes.
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        api_key = request.headers.get("X-API-Key")
        expected_key = settings.PIPELINE_API_KEY

        if not api_key:
            return jsonify({"error": "Missing API key. Provide X-API-Key header."}), 401

        api_key = api_key.strip()
        if not hmac.compare_digest(api_key, expected_key):
            logger.warning(f"Invalid API key attempt from IP: {request.remote_addr}")
            return jsonify({"error": "Invalid API key."}), 401

        logger.info(f"API key authentication successful from IP {request.remote_addr}")
        return f(*args, **kwargs)

    return decorated


def require_any_auth(f: Callable) -> Callable:
    """
    Decorator that accepts either a valid API key (X-API-Key header)
    or a valid JWT token (Authorization: Bearer <token>).
    Successful authentications are logged with the method used.
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        # 1. Try API key first
        api_key = request.headers.get("X-API-Key")
        if api_key:
            api_key = api_key.strip()
            if hmac.compare_digest(api_key, settings.PIPELINE_API_KEY):
                logger.info(f"API key authentication successful from IP {request.remote_addr}")
                return f(*args, **kwargs)
            logger.warning(f"Invalid API key attempt from IP: {request.remote_addr}")
            return jsonify({"error": "Invalid API key."}), 401

        # 2. Fall back to JWT
        token = _extract_token_from_header()
        if not token:
            return jsonify({"error": "Missing authentication. Provide X-API-Key or Bearer token."}), 401

        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
            request.user = payload.get("user")        # type: ignore[attr-defined]
            logger.info(
                f"JWT authentication successful for user '{payload.get('user')}' "
                f"from IP {request.remote_addr}"
            )
        except jwt.ExpiredSignatureError:
            logger.warning(f"Expired JWT token used from IP {request.remote_addr}")
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            logger.warning(f"Invalid JWT token used from IP {request.remote_addr}")
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
    else:
        logger.info("API key verified successfully via direct call.")
    return result
