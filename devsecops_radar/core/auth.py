import os
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
        # Read directly from os.environ to support test patching
        api_key = os.environ.get("PIPELINE_API_KEY", "disabled")
        if api_key != "disabled":
            key = request.headers.get("X-API-Key")
            if key != api_key:
                return jsonify({"error": "API key required"}), 401
        return f(*args, **kwargs)
    return decorated