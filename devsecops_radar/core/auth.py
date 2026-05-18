import jwt
import datetime
from functools import wraps
from flask import request, jsonify
from devsecops_radar.core.settings import settings

def create_token(user: str = "admin") -> str:
    payload = {
        "user": user,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=settings.JWT_EXPIRATION_HOURS),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Only enforce authentication if the admin has configured an API key.
        if settings.PIPELINE_API_KEY != "disabled":
            key = request.headers.get("X-API-Key")
            if key != settings.PIPELINE_API_KEY:
                return jsonify({"error": "API key required"}), 401
        # Without an API key, all requests are permitted (default for local use).
        return f(*args, **kwargs)
    return decorated