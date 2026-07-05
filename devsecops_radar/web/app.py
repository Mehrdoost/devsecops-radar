# devsecops_radar/web/app.py
"""
Pipeline Sentinel – Web Dashboard Factory.
Provides the Flask application with secure authentication,
CORS, rate limiting, CSP, and blueprint registration.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

# بارگذاری .env از دایرکتوری کاری کاربر (نه مسیر نصب پکیج)
from dotenv import load_dotenv

_DOTENV_PATH = Path.cwd() / ".env"
if _DOTENV_PATH.exists():
    load_dotenv(_DOTENV_PATH)

from flask import Flask, jsonify, request  # noqa: E402
from flask_cors import CORS  # noqa: E402
from loguru import logger  # noqa: E402
from werkzeug.middleware.proxy_fix import ProxyFix  # noqa: E402

from devsecops_radar.core.auth import (  # noqa: E402
    _check_rate_limit,
    _get_remote_ip,
    create_token,
    start_cleanup_thread,
)
from devsecops_radar.core.database import db_session  # noqa: E402
from devsecops_radar.core.settings import settings  # noqa: E402
from devsecops_radar.web.attack_paths.routes import attack_paths_bp  # noqa: E402
from devsecops_radar.web.dashboard.routes import dashboard_bp  # noqa: E402
from devsecops_radar.web.sentry.routes import sentry_bp  # noqa: E402
from devsecops_radar.web.summary.routes import summary_bp  # noqa: E402
from devsecops_radar.web.topology.routes import topology_bp  # noqa: E402

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def print_startup_banner(host: str, port: int, debug: bool, api_key_set: bool) -> None:
    local_ip = _get_local_ip()
    ollama_reachable = False
    try:
        import httpx
        resp = httpx.get("http://localhost:11434/api/version", timeout=1)
        if resp.status_code == 200:
            ollama_reachable = True
    except Exception:
        logger.debug("Ollama reachability check failed", exc_info=True)

    if HAS_RICH:
        console = Console()
        title = Text("🛡️  PIPELINE SENTINEL", style="bold cyan")
        subtitle = Text("DevSecOps Command Center", style="italic bright_blue")

        table = Table(show_header=False, box=None, padding=(0, 4))
        table.add_column(style="bold yellow")
        table.add_column(style="white")

        urls = []
        if host == "0.0.0.0":
            urls.append(f"http://{local_ip}:{port}")
            urls.append(f"http://127.0.0.1:{port}")
        else:
            urls.append(f"http://{host}:{port}")

        urls_str = "  •  ".join(urls)
        table.add_row("🌐 Dashboard:", urls_str)
        table.add_row("🔒 API Key Auth:", "Enabled" if api_key_set else "DISABLED")
        table.add_row("📡 Mode:", "DEBUG (Insecure)" if debug else "PRODUCTION (Waitress)")
        table.add_row("💾 Data Source:", "Database (scans & findings)")
        table.add_row("🔐 TLS:", "Not enabled – use a reverse proxy for HTTPS")

        if debug:
            table.add_row("🧠 Ollama:", "Available" if ollama_reachable else "Offline")
            table.add_row("⏱️  Worker Threads:", os.environ.get("WORKER_THREADS", "8"))

        table.add_row("🛑 Stop Server:", "Press CTRL+C")

        panel = Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style="cyan",
            padding=(1, 2),
            title_align="center",
            subtitle_align="center",
        )
        console.print(panel)
    else:
        logger.info(
            f"Pipeline Sentinel Web Server starting on {host}:{port} "
            f"({'DEBUG' if debug else 'PRODUCTION'})"
        )


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    app = Flask(__name__)

    # 1. Secret key – required for session cookies and JWT
    try:
        app.secret_key = settings.JWT_SECRET
        _jwt_available = True
    except ValueError:
        # JWT_SECRET not set – JWT auth will be disabled
        import secrets
        app.secret_key = secrets.token_hex(32)
        _jwt_available = False
        logger.warning(
            "JWT_SECRET not set. JWT authentication is DISABLED. "
            "Only API key authentication will work."
        )

    # 2. Security: Restrict maximum payload size to 1MB
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

    # 3. Trust reverse proxies (X-Forwarded-For, X-Forwarded-Proto)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[assignment]

    # 4. Configure CORS
    allowed_origins = os.environ.get(
        "CORS_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080"
    )
    origins_list = [o.strip() for o in allowed_origins.split(",") if o.strip()]
    CORS(app, resources={r"/api/*": {"origins": origins_list}})

    # 5. Content Security Policy header
    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self' http://localhost:* https://localhost:*; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    # 6. Register Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(attack_paths_bp, url_prefix="/api")
    app.register_blueprint(topology_bp, url_prefix="/api")
    app.register_blueprint(summary_bp, url_prefix="/api")
    app.register_blueprint(sentry_bp, url_prefix="/api")

    # ------------------------------------------------------------------
    # Authentication endpoint (NOW WITH RATE LIMITING)
    # ------------------------------------------------------------------
    @app.route("/api/auth/login", methods=["POST", "OPTIONS"])
    def login():
        if request.method == "OPTIONS":
            return "", 200

        # Rate limiting using the same function from auth.py
        ip = _get_remote_ip()
        if not _check_rate_limit(ip):
            logger.warning(f"Rate limit exceeded for {ip} on login endpoint.")
            return jsonify({"error": "Too many login attempts. Please slow down."}), 429

        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        try:
            data = request.get_json(force=False, silent=False)
        except Exception:
            return jsonify({"error": "Malformed JSON"}), 400

        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON payload format"}), 400

        provided_password = data.get("password")
        if (
            not provided_password
            or not isinstance(provided_password, str)
            or len(provided_password) > 128
        ):
            return jsonify({"error": "Invalid credentials"}), 401

        expected_key = settings.PIPELINE_API_KEY
        if not expected_key:
            logger.error("System configuration error: PIPELINE_API_KEY is not set.")
            return jsonify({"error": "Internal server configuration error"}), 500

        import hmac
        if hmac.compare_digest(
            provided_password.encode("utf-8"), expected_key.encode("utf-8")
        ):
            token = create_token()
            logger.info(f"Successful authentication from IP: {request.remote_addr}")
            return jsonify({"token": token}), 200

        logger.warning(f"Failed authentication attempt from IP: {request.remote_addr}")
        return jsonify({"error": "Invalid credentials"}), 401

    # ------------------------------------------------------------------
    # Error handlers
    # ------------------------------------------------------------------
    @app.errorhandler(404)
    def resource_not_found(e):
        return jsonify(error=str(e)), 404

    @app.errorhandler(413)
    def request_entity_too_large(e):
        return jsonify(error="Payload too large. Maximum size is 1MB."), 413

    @app.errorhandler(500)
    def internal_server_error(e):
        return jsonify(error="Internal server error"), 500

    # ------------------------------------------------------------------
    # Clean up scoped session after each request
    # ------------------------------------------------------------------
    @app.teardown_appcontext
    def remove_scoped_session(exception=None):
        db_session.remove()

    return app


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------
def start_server():
    app = create_app()

    host = settings.HOST or "0.0.0.0"
    port = int(settings.PORT) if settings.PORT else 8080

    api_key_set = bool(settings.PIPELINE_API_KEY)

    print_startup_banner(host, port, settings.DEBUG, api_key_set)

    if settings.DEBUG:
        logger.warning("WARNING: DEBUG mode is active. Do NOT use in production!")

    # Start rate-limiter cleanup thread
    start_cleanup_thread()

    from waitress import serve
    threads = int(os.environ.get("WORKER_THREADS", "8"))
    logger.info(f"Waitress serving on {host}:{port} with {threads} threads")
    serve(app, host=host, port=port, threads=threads)


if __name__ == "__main__":
    start_server()
