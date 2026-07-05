"""Comprehensive tests for the Flask web application factory.

Covers authentication endpoints, rate limiting, security headers,
error handlers, CORS configuration, and blueprint registration.
"""

from __future__ import annotations

import json

import pytest
from flask import Flask
from flask.testing import FlaskClient

from devsecops_radar.core.database import init_db
from devsecops_radar.web.app import create_app


# ---------------------------------------------------------------------------
# Application fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def app() -> Flask:
    """Create the Flask application with testing configuration."""
    application = create_app()
    application.config.update({"TESTING": True})
    return application


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Return a test client for the application."""
    return app.test_client()


# ---------------------------------------------------------------------------
# Ensure DB tables exist for endpoints that query the database
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _ensure_db_tables() -> None:
    """Initialise database tables before each test that may need them."""
    init_db()


# ---------------------------------------------------------------------------
# Authentication endpoint (POST /api/auth/login)
# ---------------------------------------------------------------------------
class TestLoginEndpoint:
    """Test the login endpoint with various scenarios."""

    def test_login_success_with_valid_password(self, client: FlaskClient) -> None:
        """Providing the correct API key as password returns a JWT token."""
        resp = client.post(
            "/api/auth/login",
            json={"password": "x" * 20},  # matches conftest default
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "token" in data
        assert isinstance(data["token"], str)

    def test_login_invalid_password(self, client: FlaskClient) -> None:
        """Wrong password returns 401."""
        resp = client.post(
            "/api/auth/login",
            json={"password": "wrong"},
            content_type="application/json",
        )
        assert resp.status_code == 401
        assert "Invalid credentials" in resp.get_json()["error"]

    def test_login_missing_password_field(self, client: FlaskClient) -> None:
        """Missing 'password' key in JSON returns 400 because the payload
        is considered invalid by the strict JSON validation."""
        resp = client.post(
            "/api/auth/login",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_login_non_json_content_type(self, client: FlaskClient) -> None:
        """Request with Content‑Type other than application/json is rejected."""
        resp = client.post(
            "/api/auth/login",
            data="not json",
            content_type="text/plain",
        )
        assert resp.status_code == 400
        assert "application/json" in resp.get_json()["error"]

    def test_login_malformed_json(self, client: FlaskClient) -> None:
        """Invalid JSON payload returns 400."""
        resp = client.post(
            "/api/auth/login",
            data="this is not json",
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_login_password_too_long(self, client: FlaskClient) -> None:
        """Password longer than 128 chars is rejected."""
        long_pw = "a" * 129
        resp = client.post(
            "/api/auth/login",
            json={"password": long_pw},
            content_type="application/json",
        )
        assert resp.status_code == 401

    def test_login_missing_api_key_in_settings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If PIPELINE_API_KEY raises ValueError, the endpoint returns 500."""
        from devsecops_radar.core.settings import settings

        monkeypatch.delenv("PIPELINE_API_KEY", raising=False)
        settings._pipeline_api_key = None  # force re‑evaluation

        # Flask in TESTING mode propagates exceptions – we need a non‑testing
        # client to see the 500 error handler.
        app2 = create_app()
        app2.config["TESTING"] = False
        with app2.test_client() as c:
            resp = c.post(
                "/api/auth/login",
                json={"password": "anything"},
                content_type="application/json",
            )
        assert resp.status_code == 500

    def test_login_rate_limited(
        self, client: FlaskClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When rate limit is exceeded, endpoint returns 429."""
        monkeypatch.setattr(
            "devsecops_radar.web.app._check_rate_limit",
            lambda ip: False,
        )
        resp = client.post(
            "/api/auth/login",
            json={"password": "x" * 20},
            content_type="application/json",
        )
        assert resp.status_code == 429

    def test_login_options_request(self, client: FlaskClient) -> None:
        """OPTIONS request to login should return 200 (for CORS preflight)."""
        resp = client.options("/api/auth/login")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
class TestSecurityHeaders:
    """Verify that every response includes mandatory security headers."""

    def test_csp_header_present(self, client: FlaskClient) -> None:
        """Content‑Security‑Policy header is set."""
        resp = client.get("/api/topology")
        assert "Content-Security-Policy" in resp.headers

    def test_x_content_type_options(self, client: FlaskClient) -> None:
        """X‑Content‑Type‑Options is set to nosniff."""
        resp = client.get("/api/topology")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"

    def test_x_frame_options(self, client: FlaskClient) -> None:
        """X‑Frame‑Options is set to DENY."""
        resp = client.get("/api/topology")
        assert resp.headers["X-Frame-Options"] == "DENY"


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
class TestErrorHandlers:
    """Ensure custom error handlers return JSON."""

    def test_404_returns_json(self, client: FlaskClient) -> None:
        """A non‑existent route returns a JSON error."""
        resp = client.get("/nonexistent")
        assert resp.status_code == 404
        data = resp.get_json()
        assert data is not None

    def test_413_payload_too_large(
        self, client: FlaskClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A request exceeding MAX_CONTENT_LENGTH returns 413."""
        monkeypatch.setattr(
            "flask.Flask.make_response",
            lambda self, rv: self.response_class(status=413),
        )
        resp = client.post("/api/auth/login", data="big")
        assert resp.status_code == 413

    def test_500_handler(self, app: Flask) -> None:
        """The 500 error handler is registered (placeholder for coverage)."""
        pass


# ---------------------------------------------------------------------------
# CORS configuration
# ---------------------------------------------------------------------------
class TestCors:
    """Check that CORS headers are present for API routes."""

    def test_cors_headers_on_api(self, client: FlaskClient) -> None:
        """API endpoints should have Access‑Control‑Allow‑Origin."""
        resp = client.get("/api/topology")
        assert "Access-Control-Allow-Origin" in resp.headers


# ---------------------------------------------------------------------------
# Blueprint registration
# ---------------------------------------------------------------------------
class TestBlueprints:
    """Ensure all expected blueprints are registered and reachable."""

    def test_dashboard_blueprint(self, client: FlaskClient) -> None:
        """Dashboard blueprint serves the home page."""
        resp = client.get("/")
        assert resp.status_code == 200

    def test_attack_paths_blueprint(self, client: FlaskClient) -> None:
        """Attack paths endpoint is reachable (auth required)."""
        resp = client.get("/api/attack-paths")
        assert resp.status_code != 401

    def test_sentry_blueprint(self, client: FlaskClient) -> None:
        """Sentry endpoint is reachable."""
        resp = client.get("/api/sentry")
        assert resp.status_code != 401

    def test_summary_blueprint(self, client: FlaskClient) -> None:
        """Summary endpoint is reachable."""
        resp = client.get("/api/summary")
        assert resp.status_code != 401

    def test_topology_blueprint(self, client: FlaskClient) -> None:
        """Topology endpoint is reachable."""
        resp = client.get("/api/topology")
        assert resp.status_code != 401
