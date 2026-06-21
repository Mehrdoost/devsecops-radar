"""Tests for authentication and authorisation module (updated – no internal rate limiting)."""

from contextlib import contextmanager
from unittest.mock import patch

import jwt
import pytest
from flask import Flask, jsonify, request
from loguru import logger

from devsecops_radar.core.auth import (
    _extract_token_from_header,
    create_token,
    login_required,
    require_any_auth,
    require_api_key,
    verify_api_key,
)


# ---------------------------------------------------------------------------
# Helper to capture loguru output
# ---------------------------------------------------------------------------
@contextmanager
def capture_loguru(level: str = "TRACE"):
    messages: list[str] = []

    def sink(msg):
        messages.append(str(msg))

    handler_id = logger.add(sink, level=level, format="{message}")
    try:
        yield messages
    finally:
        logger.remove(handler_id)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def app():
    app = Flask(__name__)
    return app


@pytest.fixture
def mock_settings():
    with patch("devsecops_radar.core.auth.settings.JWT_SECRET", "test-secret"), \
         patch("devsecops_radar.core.auth.settings.PIPELINE_API_KEY", "test-api-key"):
        yield


# ---------------------------------------------------------------------------
# Tests for _extract_token_from_header
# ---------------------------------------------------------------------------
class TestExtractToken:
    def test_valid_header(self, app):
        with app.test_request_context(headers={"Authorization": "Bearer abc123"}):
            assert _extract_token_from_header() == "abc123"

    def test_missing_header(self, app):
        with app.test_request_context():
            assert _extract_token_from_header() is None

    def test_header_not_starting_with_bearer(self, app):
        with app.test_request_context(headers={"Authorization": "Basic xyz"}):
            assert _extract_token_from_header() is None

    def test_bearer_no_token(self, app):
        with app.test_request_context(headers={"Authorization": "Bearer "}):
            assert _extract_token_from_header() == ""


# ---------------------------------------------------------------------------
# Tests for create_token
# ---------------------------------------------------------------------------
class TestCreateToken:
    def test_success(self, mock_settings):
        with patch("devsecops_radar.core.auth.jwt.encode") as mock_encode:
            mock_encode.return_value = "fake-jwt"
            token = create_token("admin")
            assert token == "fake-jwt"
            mock_encode.assert_called_once()
            call_args = mock_encode.call_args[1]
            assert call_args["algorithm"] == "HS256"

    def test_failure_raises_runtime_error(self, mock_settings):
        with patch("devsecops_radar.core.auth.jwt.encode", side_effect=Exception("encoding error")), \
             capture_loguru() as msgs:
            with pytest.raises(RuntimeError, match="Could not generate"):
                create_token()
        assert any("JWT generation failed" in m for m in msgs)


# ---------------------------------------------------------------------------
# Tests for login_required decorator
# ---------------------------------------------------------------------------
class TestLoginRequired:
    @pytest.fixture
    def decorated_function(self):
        @login_required
        def test_view():
            return jsonify({"status": "ok"}), 200
        return test_view

    def test_success_valid_token(self, app, mock_settings, decorated_function):
        with patch("devsecops_radar.core.auth.jwt.decode") as mock_decode:
            mock_decode.return_value = {"user": "admin"}
            with app.test_request_context(headers={"Authorization": "Bearer validtoken"}):
                resp, code = decorated_function()
                assert code == 200
                assert resp.json["status"] == "ok"
                assert request.user == "admin"

    def test_missing_token_returns_401(self, app, mock_settings, decorated_function):
        with app.test_request_context():
            resp, code = decorated_function()
            assert code == 401
            assert "Missing or invalid Authorization" in resp.json["error"]

    def test_expired_token_returns_401(self, app, mock_settings, decorated_function):
        with patch("devsecops_radar.core.auth.jwt.decode", side_effect=jwt.ExpiredSignatureError):
            with app.test_request_context(headers={"Authorization": "Bearer expired"}):
                resp, code = decorated_function()
                assert code == 401
                assert "expired" in resp.json["error"].lower()

    def test_invalid_token_returns_401(self, app, mock_settings, decorated_function):
        with patch("devsecops_radar.core.auth.jwt.decode", side_effect=jwt.InvalidTokenError):
            with app.test_request_context(headers={"Authorization": "Bearer invalid"}):
                resp, code = decorated_function()
                assert code == 401
                assert "Invalid token" in resp.json["error"]

    def test_unexpected_decode_error_returns_500(self, app, mock_settings, decorated_function):
        with patch("devsecops_radar.core.auth.jwt.decode", side_effect=Exception("unexpected")), \
             capture_loguru() as msgs:
            with app.test_request_context(headers={"Authorization": "Bearer something"}):
                resp, code = decorated_function()
                assert code == 500
                assert "Authentication failed" in resp.json["error"]
        assert any("Unexpected error" in m for m in msgs)


# ---------------------------------------------------------------------------
# Tests for require_api_key decorator
# ---------------------------------------------------------------------------
class TestRequireApiKey:
    @pytest.fixture
    def decorated_function(self):
        @require_api_key
        def test_view():
            return jsonify({"status": "ok"}), 200
        return test_view

    def test_success_valid_key(self, app, mock_settings, decorated_function):
        with app.test_request_context(headers={"X-API-Key": "test-api-key"}):
            resp, code = decorated_function()
            assert code == 200
            assert resp.json["status"] == "ok"

    def test_missing_key_returns_401(self, app, mock_settings, decorated_function):
        with app.test_request_context():
            resp, code = decorated_function()
            assert code == 401
            assert "Missing API key" in resp.json["error"]

    def test_invalid_key_returns_401(self, app, mock_settings, decorated_function):
        with capture_loguru() as msgs:
            with app.test_request_context(
                environ_base={"REMOTE_ADDR": "192.168.1.1"},
                headers={"X-API-Key": "wrong-key"},
            ):
                resp, code = decorated_function()
        assert code == 401
        assert "Invalid API key" in resp.json["error"]
        assert any("Invalid API key attempt" in m for m in msgs)

    def test_key_with_whitespace_stripped(self, app, mock_settings, decorated_function):
        with app.test_request_context(headers={"X-API-Key": "  test-api-key  "}):
            resp, code = decorated_function()
            assert code == 200


# ---------------------------------------------------------------------------
# Tests for require_any_auth decorator
# ---------------------------------------------------------------------------
class TestRequireAnyAuth:
    @pytest.fixture
    def decorated_function(self):
        @require_any_auth
        def test_view():
            return jsonify({"status": "ok"}), 200
        return test_view

    def test_success_api_key(self, app, mock_settings, decorated_function):
        with app.test_request_context(headers={"X-API-Key": "test-api-key"}):
            resp, code = decorated_function()
            assert code == 200
            assert resp.json["status"] == "ok"

    def test_success_jwt(self, app, mock_settings, decorated_function):
        with patch("devsecops_radar.core.auth.jwt.decode") as mock_decode:
            mock_decode.return_value = {"user": "admin"}
            with app.test_request_context(headers={"Authorization": "Bearer validtoken"}):
                resp, code = decorated_function()
                assert code == 200
                assert resp.json["status"] == "ok"

    def test_no_auth_returns_401(self, app, mock_settings, decorated_function):
        with app.test_request_context():
            resp, code = decorated_function()
            assert code == 401
            assert "Missing authentication" in resp.json["error"]

    def test_invalid_api_key_returns_401(self, app, mock_settings, decorated_function):
        with app.test_request_context(headers={"X-API-Key": "wrong"}):
            resp, code = decorated_function()
            assert code == 401
            assert "Invalid API key" in resp.json["error"]

    def test_invalid_jwt_returns_401(self, app, mock_settings, decorated_function):
        with patch("devsecops_radar.core.auth.jwt.decode", side_effect=jwt.InvalidTokenError):
            with app.test_request_context(headers={"Authorization": "Bearer bad"}):
                resp, code = decorated_function()
                assert code == 401
                assert "Invalid token" in resp.json["error"]


# ---------------------------------------------------------------------------
# Tests for verify_api_key
# ---------------------------------------------------------------------------
class TestVerifyApiKey:
    def test_correct_key_returns_true(self, mock_settings):
        assert verify_api_key("test-api-key") is True

    def test_wrong_key_returns_false(self, mock_settings):
        with capture_loguru() as msgs:
            result = verify_api_key("wrong")
        assert result is False
        assert any("Invalid API key" in m for m in msgs)

    def test_empty_key_returns_false(self, mock_settings):
        assert verify_api_key("") is False

    def test_none_returns_false(self, mock_settings):
        assert verify_api_key(None) is False

    def test_strips_whitespace(self, mock_settings):
        assert verify_api_key("  test-api-key  ") is True
