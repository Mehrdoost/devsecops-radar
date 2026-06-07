import hmac
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any

import jwt
from flask import jsonify, request
from loguru import logger

from devsecops_radar.core.settings import settings


def create_token(user: str = "admin") -> str:
    """Generate a secure JWT token for the authenticated user."""
    try:
        payload = {
            "user": user,
            "exp": datetime.now(UTC) + timedelta(hours=1),
            "iat": datetime.now(UTC),
        }
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")
        return token
    except Exception as e:
        logger.error(f"JWT generation failed: {str(e)}")
        raise RuntimeError("Could not generate authentication token.") from e


def login_required(f: Callable) -> Callable:
    """
    Decorator to protect API endpoints using JWT Bearer token.
    (Unchanged for backward compatibility)
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header. Expected Bearer token."}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
            request.user = payload.get("user")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token."}), 401
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {str(e)}")
            return jsonify({"error": "Authentication failed."}), 500

        return f(*args, **kwargs)

    return decorated


def require_api_key(f: Callable) -> Callable:
    """
    Decorator to protect API endpoints using a simple API Key (X-API-Key header).
    Compares securely using constant‑time comparison.
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        api_key = request.headers.get("X-API-Key")
        expected_key = settings.PIPELINE_API_KEY

        if not api_key:
            return jsonify({"error": "Missing API key. Provide X-API-Key header."}), 401

        if not hmac.compare_digest(api_key, expected_key):
            logger.warning(f"Invalid API key attempt from IP: {request.remote_addr}")
            return jsonify({"error": "Invalid API key."}), 401

        return f(*args, **kwargs)

    return decorated


def verify_api_key(provided_key: str) -> bool:
    """Constant-time comparison of a provided API key against the system key."""
    if not provided_key:
        return False
    return hmac.compare_digest(provided_key, settings.PIPELINE_API_KEY)
