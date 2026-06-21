"""Tests for the Flask application factory and web entry points – rate‑limiting disabled."""

import os
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Set required env vars BEFORE any imports
# ---------------------------------------------------------------------------
os.environ["JWT_SECRET"] = "a" * 32
os.environ["PIPELINE_API_KEY"] = "valid-api-key"

# ---------------------------------------------------------------------------
# Mock heavy / optional dependencies so they are never truly imported
# ---------------------------------------------------------------------------
with patch.dict("sys.modules", {
    "rich": MagicMock(),
    "rich.console": MagicMock(),
    "rich.panel": MagicMock(),
    "rich.table": MagicMock(),
    "rich.text": MagicMock(),
    "waitress": MagicMock(),
    "flask_cors": MagicMock(),
    "flask_cors.CORS": MagicMock(),
}):
    import devsecops_radar.web.app as app_module
    from devsecops_radar.web.app import (
        _get_local_ip,
        create_app,
        print_startup_banner,
    )

from devsecops_radar.core.settings import settings as settings_instance


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _disable_rate_limiting(monkeypatch):
    """Replace the rate_limited decorator with a no‑op."""
    monkeypatch.setattr(app_module, "rate_limited", lambda *a, **kw: lambda f: f)


@pytest.fixture
def app():
    with patch.object(settings_instance, "DEBUG", False):
        app = create_app()

    # Unwrap any rate‑limited view functions that were decorated at import time
    with app.app_context():
        for endpoint in ("login", "dashboard.api_report", "dashboard.api_simulate"):
            if endpoint in app.view_functions:
                original = app.view_functions[endpoint]
                while hasattr(original, "__wrapped__"):
                    original = original.__wrapped__
                app.view_functions[endpoint] = original

    yield app


@pytest.fixture
def client(app):
    with app.test_client() as client:
        yield client


# ---------------------------------------------------------------------------
# _get_local_ip
# ---------------------------------------------------------------------------
class TestGetLocalIp:
    def test_returns_ip(self):
        assert _get_local_ip()

    @patch("socket.socket")
    def test_fallback_on_error(self, mock_sock):
        mock_sock.return_value.__enter__.return_value.connect.side_effect = OSError
        assert _get_local_ip() == "127.0.0.1"


# ---------------------------------------------------------------------------
# print_startup_banner
# ---------------------------------------------------------------------------
class TestPrintStartupBanner:
    def test_with_rich(self, monkeypatch):
        monkeypatch.setattr(app_module, "HAS_RICH", True)
        mock_console = MagicMock()
        with patch.object(app_module, "Console", mock_console):
            print_startup_banner("0.0.0.0", 8080, False)
        mock_console.assert_called_once()

    def test_without_rich(self, monkeypatch):
        monkeypatch.setattr(app_module, "HAS_RICH", False)
        print_startup_banner("127.0.0.1", 5000, True)


# ---------------------------------------------------------------------------
# create_app
# ---------------------------------------------------------------------------
class TestCreateApp:
    def test_blueprints_registered(self, app):
        bp_names = {bp.name for bp in app.iter_blueprints()}
        assert "dashboard" in bp_names
        assert "attack_paths" in bp_names
        assert "topology" in bp_names
        assert "summary" in bp_names
        assert "sentry" in bp_names

    def test_max_content_length_set(self, app):
        assert app.config["MAX_CONTENT_LENGTH"] == 1 * 1024 * 1024

    def test_404_handler(self, client):
        resp = client.get("/nonexistent")
        assert resp.status_code == 404
        assert "error" in resp.json

    def test_session_teardown_registered(self, app):
        teardown_funcs = app.teardown_appcontext_funcs
        assert teardown_funcs


# ---------------------------------------------------------------------------
# Login endpoint
# ---------------------------------------------------------------------------
class TestLoginEndpoint:
    def test_malformed_json(self, client):
        resp = client.post(
            "/api/auth/login",
            data="not json",
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "Malformed JSON" in resp.json["error"]

    def test_missing_content_type(self, client):
        resp = client.post("/api/auth/login", data="{}")
        assert resp.status_code == 400

    def test_missing_password(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"password": ""},
            content_type="application/json",
        )
        assert resp.status_code == 401

    def test_password_too_long(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"password": "a" * 200},
            content_type="application/json",
        )
        assert resp.status_code == 401

    def test_invalid_password(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"password": "wrong-key"},
            content_type="application/json",
        )
        assert resp.status_code == 401

    def test_valid_login(self, client):
        with patch.object(app_module, "create_token", return_value="fake-jwt-token") as mock_token:
            resp = client.post(
                "/api/auth/login",
                json={"password": "valid-api-key"},
                content_type="application/json",
            )
        assert resp.status_code == 200
        assert resp.json["token"] == "fake-jwt-token"
        mock_token.assert_called_once()

    def test_missing_api_key_in_settings(self, client, monkeypatch):
        monkeypatch.setattr(app_module.settings, "PIPELINE_API_KEY", "")
        resp = client.post(
            "/api/auth/login",
            json={"password": "anything"},
            content_type="application/json",
        )
        assert resp.status_code == 500
