import os
from functools import wraps

from flask import jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from devsecops_radar.core.settings import settings

_HASHED_API_KEY = None


def _get_hashed_key() -> str:
    global _HASHED_API_KEY
    if _HASHED_API_KEY is None and settings.PIPELINE_API_KEY != "disabled":
        _HASHED_API_KEY = generate_password_hash(settings.PIPELINE_API_KEY)
    return _HASHED_API_KEY


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = os.environ.get("PIPELINE_API_KEY", "disabled")
        if api_key == "disabled":
            return f(*args, **kwargs)

        key = request.headers.get("X-API-Key")
        if not key:
            return jsonify({"error": "API key required"}), 401

        hashed = _get_hashed_key()
        if hashed and check_password_hash(hashed, key):
            return f(*args, **kwargs)

        return jsonify({"error": "API key required"}), 401
    return decorated


def create_token(user: str = "admin") -> str:
    import datetime

    import jwt
    payload = {
        "user": user,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=settings.JWT_EXPIRATION_HOURS),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
