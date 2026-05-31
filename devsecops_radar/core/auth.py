import os
from functools import wraps

from flask import jsonify, request


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Read directly from os.environ so tests can monkeypatch
        api_key = os.environ.get("PIPELINE_API_KEY", "disabled")
        if api_key == "disabled":
            return f(*args, **kwargs)

        key = request.headers.get("X-API-Key")
        if not key:
            return jsonify({"error": "API key required"}), 401

        # Compare plaintext keys (secure enough for localhost / API key use)
        if key == api_key:
            return f(*args, **kwargs)

        return jsonify({"error": "API key required"}), 401
    return decorated


def create_token(user: str = "admin") -> str:
    import datetime

    import jwt

    from devsecops_radar.core.settings import settings

    payload = {
        "user": user,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=settings.JWT_EXPIRATION_HOURS),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
