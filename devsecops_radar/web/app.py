import hmac
import os
import socket
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS
from loguru import logger
from werkzeug.exceptions import BadRequest

from devsecops_radar.core.auth import create_token
from devsecops_radar.core.settings import settings
from devsecops_radar.web.attack_paths.routes import attack_paths_bp
from devsecops_radar.web.dashboard.routes import dashboard_bp
from devsecops_radar.web.sentry.routes import sentry_bp
from devsecops_radar.web.summary.routes import summary_bp
from devsecops_radar.web.topology.routes import topology_bp

# Optional: Rich for fancy terminal output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


def _get_local_ip() -> str:
    """Safely determine the local network IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _check_file(path: str) -> bool:
    """Check if a file exists (non-sensitive)."""
    return Path(path).is_file()


def print_startup_banner(host: str, port: int, debug: bool) -> None:
    """
    Display a rich, informative startup banner.
    Falls back to plain text if Rich is not installed.
    """
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
        pass

    if HAS_RICH:
        console = Console()
        # Title
        title = Text("🛡️  PIPELINE SENTINEL", style="bold cyan")
        subtitle = Text("DevSecOps Command Center", style="italic bright_blue")

        # Status table
        table = Table(show_header=False, box=None, padding=(0, 4))
        table.add_column(style="bold yellow")
        table.add_column(style="white")

        # Determine actual access URLs
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

        # Additional security/performance info
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
        # Fallback minimal banner
        logger.info(
            f"Pipeline Sentinel Web Server starting on {host}:{port} "
            f"({'DEBUG' if debug else 'PRODUCTION'})"
        )


def create_app() -> Flask:
    """
    Application Factory for the DevSecOps Radar Web Gateway.
    Implements secure defaults, CORS, and modular routing.
    """
    app = Flask(__name__)

    # 1. Security: Restrict maximum payload size to 1MB to prevent memory DoS attacks
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

    # 2. Security: Enable Cross-Origin Resource Sharing for the frontend
    #    In production, restrict origins to your actual domain(s).
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # 3. Architecture: Register Blueprints with corrected prefixes
    #    dashboard_bp handles both the root HTML and /api/... endpoints
    app.register_blueprint(dashboard_bp)

    #    Other Blueprints with /api prefix (their routes already start without /api)
    app.register_blueprint(attack_paths_bp, url_prefix="/api")
    app.register_blueprint(topology_bp, url_prefix="/api")
    app.register_blueprint(summary_bp, url_prefix="/api")
    app.register_blueprint(sentry_bp, url_prefix="/api")

    #    simulation_bp removed by user – no longer registered

    @app.route("/api/auth/login", methods=["POST"])
    def login():
        """
        Secure authentication endpoint.
        Uses constant-time comparison to prevent timing side-channel attacks.
        """
        try:
            data = request.get_json(force=True, silent=True)
            if not data or not isinstance(data, dict):
                return jsonify({"error": "Invalid JSON payload format"}), 400
        except BadRequest:
            return jsonify({"error": "Malformed request"}), 400

        provided_password = data.get("password")

        # Security: Input validation
        if (
            not provided_password
            or not isinstance(provided_password, str)
            or len(provided_password) > 128
        ):
            # Generic error message to prevent username/password enumeration
            return jsonify({"error": "Invalid credentials"}), 401

        # Fetch the expected key securely
        expected_key = settings.PIPELINE_API_KEY
        if not expected_key:
            logger.error("System configuration error: PIPELINE_API_KEY is not set.")
            return jsonify({"error": "Internal server configuration error"}), 500

        # Security: hmac.compare_digest defends against timing attacks
        if hmac.compare_digest(
            provided_password.encode("utf-8"), expected_key.encode("utf-8")
        ):
            token = create_token()
            logger.info("Successful authentication via API. Token generated.")
            return jsonify({"token": token}), 200

        logger.warning(f"Failed authentication attempt from IP: {request.remote_addr}")
        return jsonify({"error": "Invalid credentials"}), 401

    # Global error handlers for cleaner JSON API responses
    @app.errorhandler(404)
    def resource_not_found(e):
        return jsonify(error=str(e)), 404

    @app.errorhandler(413)
    def request_entity_too_large(e):
        return jsonify(error="Payload too large. Maximum size is 1MB."), 413

    @app.errorhandler(500)
    def internal_server_error(e):
        return jsonify(error="Internal server error"), 500

    return app


def start_server():
    """
    Bootstraps the web server.
    Uses Waitress WSGI for production, falls back to Flask dev server ONLY if explicitly configured.
    """
    app = create_app()

    host = settings.HOST or "0.0.0.0"
    port = int(settings.PORT) if settings.PORT else 8080


    print_startup_banner(host, port, settings.DEBUG)

    if settings.DEBUG:
        logger.warning(
            "WARNING: Running in DEBUG mode. DO NOT use this in a production environment!"
        )
        # Development mode
        app.run(host=host, port=port, debug=True)
    else:
        # Production mode using a proper WSGI server
        from waitress import serve

        logger.info(f"Waitress serving on {host}:{port}")
        serve(app, host=host, port=port, threads=8)


if __name__ == "__main__":
    start_server()
