"""Tests for the Flask application factory and web entry points."""

import os
import time
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
        _LOGIN_MAX_ATTEMPTS,
        _LOGIN_WINDOW_SECONDS,
        _check_login_rate,
        _get_local_ip,
        _login_rate_store,
        create_app,
        print_startup_banner,
    )

from devsecops_radar.core.settings import settings as settings_instance


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def clean_rate_limits():
    _login_rate_store.clear()


@pytest.fixture
def app():
    with patch.object(settings_instance, "DEBUG", False):
        return create_app()


@pytest.fixture
def client(app):
    with app.test_client() as client:
        yield client


# ---------------------------------------------------------------------------
# _check_login_rate
# ---------------------------------------------------------------------------
class TestCheckLoginRate:
    def test_allow_first_requests(self):
        ip = "1.2.3.4"
        for _ in range(_LOGIN_MAX_ATTEMPTS):
            assert _check_login_rate(ip) is True
        assert _check_login_rate(ip) is False

    def test_window_expiry(self, monkeypatch):
        ip = "5.6.7.8"
        now = time.time()
        monkeypatch.setattr(time, "time", lambda: now)
        for _ in range(_LOGIN_MAX_ATTEMPTS):
            assert _check_login_rate(ip) is True
        assert _check_login_rate(ip) is False
        monkeypatch.setattr(time, "time", lambda: now + _LOGIN_WINDOW_SECONDS + 1)
        assert _check_login_rate(ip) is True

    def test_different_ips_independent(self):
        ip1 = "10.0.0.1"
        ip2 = "10.0.0.2"
        for _ in range(_LOGIN_MAX_ATTEMPTS):
            assert _check_login_rate(ip1) is True
        assert _check_login_rate(ip1) is False
        assert _check_login_rate(ip2) is True


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

    def test_session_teardown(self, client):
        mock_remove = MagicMock()
        with patch.object(app_module.db_session, "remove", mock_remove):
            client.get("/api/summary")
        mock_remove.assert_called()


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
        # Patch the settings object used by app.py directly
        monkeypatch.setattr(app_module.settings, "PIPELINE_API_KEY", "")
        resp = client.post(
            "/api/auth/login",
            json={"password": "anything"},
            content_type="application/json",
        )
        assert resp.status_code == 500

    def test_rate_limit_exceeded(self, client):
        ip = "127.0.0.1"
        _login_rate_store[ip] = [time.time()] * _LOGIN_MAX_ATTEMPTS
        try:
            resp = client.post(
                "/api/auth/login",
                json={"password": "valid-api-key"},
                content_type="application/json",
            )
            assert resp.status_code == 429
            assert "Too many login attempts" in resp.json["error"]
        finally:
            _login_rate_store.pop(ip, None)
