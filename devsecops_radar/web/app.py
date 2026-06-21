# devsecops_radar/web/app.py
import hmac
import os
import socket
import threading
import time
from collections.abc import Callable
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS
from loguru import logger
from werkzeug.exceptions import BadRequest

from devsecops_radar.core.auth import create_token
from devsecops_radar.core.database import db_session
from devsecops_radar.core.settings import settings
from devsecops_radar.web.attack_paths.routes import attack_paths_bp
from devsecops_radar.web.dashboard.routes import dashboard_bp
from devsecops_radar.web.sentry.routes import sentry_bp
from devsecops_radar.web.summary.routes import summary_bp
from devsecops_radar.web.topology.routes import topology_bp

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ---------------------------------------------------------------------------
# In‑memory rate limiter (unchanged)
# ---------------------------------------------------------------------------
_rate_store: dict[str, list[float]] = {}
_rate_lock = threading.Lock()


def _cleanup_rate_store(now: float, window: float) -> None:
    expired = [ip for ip, stamps in _rate_store.items()
               if all(now - t >= window for t in stamps)]
    for ip in expired:
        del _rate_store[ip]


def rate_limited(max_requests: int, window_seconds: float):
    """Decorator that limits *max_requests* per *window_seconds* per IP."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = time.time()
            with _rate_lock:
                _cleanup_rate_store(now, window_seconds)
                timestamps = _rate_store.get(ip, [])
                timestamps = [t for t in timestamps if now - t < window_seconds]
                if len(timestamps) >= max_requests:
                    _rate_store[ip] = timestamps
                    return jsonify({
                        "error": "Rate limit exceeded. Please slow down."
                    }), 429
                timestamps.append(now)
                _rate_store[ip] = timestamps
            return f(*args, **kwargs)
        return wrapper
    return decorator


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


def _check_file(path: str) -> bool:
    return Path(path).is_file()


def print_startup_banner(host: str, port: int, debug: bool) -> None:
    api_key_set = bool(settings.PIPELINE_API_KEY)
    local_ip = _get_local_ip()
    findings_file = os.environ.get("FINDINGS_FILE", "findings.json")
    findings_exist = _check_file(findings_file)
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
        table.add_row("🔒 API Key Auth:",
                      "Enabled" if api_key_set else "DISABLED – Set PIPELINE_API_KEY")
        table.add_row("📡 Mode:",
                      "DEBUG (Insecure)" if debug else "PRODUCTION (Waitress)")
        table.add_row("📁 Findings File:",
                      "Loaded" if findings_exist else "Not Found (use CLI first)")
        table.add_row("🧠 Ollama:",
                      "Available" if ollama_reachable else "Offline (AI analysis disabled)")
        table.add_row("⏱️  Worker Threads:", "8")
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

    # 1. Security: Restrict maximum payload size to 1MB to prevent memory DoS
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

    # 2. Security: Configure CORS using environment variable
    allowed_origins = os.environ.get(
        "CORS_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080"
    )
    origins_list = [o.strip() for o in allowed_origins.split(",") if o.strip()]
    CORS(app, resources={r"/api/*": {"origins": origins_list}})

    # 3. Architecture: Register Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(attack_paths_bp, url_prefix="/api")
    app.register_blueprint(topology_bp, url_prefix="/api")
    app.register_blueprint(summary_bp, url_prefix="/api")
    app.register_blueprint(sentry_bp, url_prefix="/api")

    # ------------------------------------------------------------------
    # Global auth check – EXCLUDES OPTIONS requests for CORS preflight
    # ------------------------------------------------------------------
    @app.before_request
    def global_auth_check():
        # Allow preflight requests to pass through without auth
        if request.method == "OPTIONS":
            return None

        if request.path.startswith("/api/") and request.path != "/api/auth/login":
            if not request.headers.get("X-API-Key") and not request.headers.get("Authorization"):
                return jsonify({"error": "Authentication required"}), 401

    # ------------------------------------------------------------------
    # Authentication endpoint (with rate limiting & audit trail)
    # ------------------------------------------------------------------
    @app.route("/api/auth/login", methods=["POST", "OPTIONS"])
    @rate_limited(max_requests=5, window_seconds=60)
    def login():
        if request.method == "OPTIONS":
            return "", 200

        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        try:
            data = request.get_json(force=False, silent=False)
        except BadRequest:
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

    print_startup_banner(host, port, settings.DEBUG)

    if settings.DEBUG:
        logger.warning("WARNING: DEBUG mode is active. Do NOT use in production!")

    from waitress import serve
    threads = int(os.environ.get("WORKER_THREADS", "8"))
    logger.info(f"Waitress serving on {host}:{port} with {threads} threads")
    serve(app, host=host, port=port, threads=threads)


if __name__ == "__main__":
    start_server()
