from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import flask
import jwt
import pytest

from devsecops_radar.core.auth import (
    create_token,
    logger,
    login_required,
    require_api_key,
    verify_api_key,
)
from devsecops_radar.core.settings import settings

app = flask.Flask(__name__)


# ------------------------------------------------------------
# Tests for create_token
# ------------------------------------------------------------
class TestCreateToken:
    def test_success(self):
        with patch.object(settings, "JWT_SECRET", "secret"), \
             patch("devsecops_radar.core.auth.jwt.encode", return_value="mocked_token") as mock_encode, \
             patch("devsecops_radar.core.auth.datetime") as mock_datetime:
            fixed_now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
            mock_datetime.now.return_value = fixed_now

            token = create_token("testuser")
            assert token == "mocked_token"

            expected_payload = {
                "user": "testuser",
                "exp": fixed_now + timedelta(hours=1),
                "iat": fixed_now,
            }
            mock_encode.assert_called_once_with(expected_payload, "secret", algorithm="HS256")

    def test_jwt_encode_raises_exception(self):
        with patch.object(settings, "JWT_SECRET", "secret"), \
             patch("devsecops_radar.core.auth.jwt.encode", side_effect=Exception("jwt error")), \
             patch.object(logger, "error") as mock_log:
            with pytest.raises(RuntimeError, match="Could not generate authentication token."):
                create_token("admin")
            mock_log.assert_called_once_with("JWT generation failed: jwt error")


# ------------------------------------------------------------
# Tests for verify_api_key
# ------------------------------------------------------------
class TestVerifyApiKey:
    def test_empty_key_returns_false(self):
        assert verify_api_key("") is False

    def test_matching_key(self):
        with patch.object(settings, "PIPELINE_API_KEY", "supersecret"), \
             patch("devsecops_radar.core.auth.hmac.compare_digest", return_value=True) as mock_compare:
            result = verify_api_key("supersecret")
            assert result is True
            mock_compare.assert_called_once_with("supersecret", "supersecret")

    def test_non_matching_key(self):
        with patch.object(settings, "PIPELINE_API_KEY", "supersecret"), \
             patch("devsecops_radar.core.auth.hmac.compare_digest", return_value=False):
            assert verify_api_key("wrong") is False


# ------------------------------------------------------------
# Helper view for decorator tests
# ------------------------------------------------------------
def dummy_view(*args, **kwargs):
    return flask.jsonify({"data": "ok"})


# ------------------------------------------------------------
# Tests for login_required
# ------------------------------------------------------------
class TestLoginRequired:
    @pytest.fixture(autouse=True)
    def setup_settings(self):
        with patch.object(settings, "JWT_SECRET", "testsecret"):
            yield

    def test_missing_authorization_header(self):
        decorated = login_required(dummy_view)
        with app.test_request_context():
            response, status = decorated()
            assert status == 401
            assert b"Missing or invalid Authorization header" in response.data

    def test_header_not_start_with_bearer(self):
        decorated = login_required(dummy_view)
        with app.test_request_context(headers={"Authorization": "Basic xyz"}):
            response, status = decorated()
            assert status == 401
            assert b"Missing or invalid Authorization header" in response.data

    def test_valid_token(self):
        decorated = login_required(dummy_view)
        with app.test_request_context(headers={"Authorization": "Bearer validtoken"}), \
             patch("devsecops_radar.core.auth.jwt.decode") as mock_decode:
            mock_decode.return_value = {"user": "admin"}
            # Successful authentication returns the view result directly (a Response object)
            response = decorated()
            assert response.status_code == 200
            assert b'"data":"ok"' in response.data
            assert flask.request.user == "admin"

    def test_expired_token(self):
        decorated = login_required(dummy_view)
        with app.test_request_context(headers={"Authorization": "Bearer expired"}), \
             patch("devsecops_radar.core.auth.jwt.decode") as mock_decode:
            mock_decode.side_effect = jwt.ExpiredSignatureError
            response, status = decorated()
            assert status == 401
            assert b"Token has expired" in response.data

    def test_invalid_token(self):
        decorated = login_required(dummy_view)
        with app.test_request_context(headers={"Authorization": "Bearer invalid"}), \
             patch("devsecops_radar.core.auth.jwt.decode") as mock_decode:
            mock_decode.side_effect = jwt.InvalidTokenError
            response, status = decorated()
            assert status == 401
            assert b"Invalid token." in response.data

    def test_unexpected_error_during_decode(self):
        decorated = login_required(dummy_view)
        with app.test_request_context(headers={"Authorization": "Bearer broken"}), \
             patch("devsecops_radar.core.auth.jwt.decode", side_effect=RuntimeError("oops")), \
             patch.object(logger, "error") as mock_log:
            response, status = decorated()
            assert status == 500
            assert b"Authentication failed." in response.data
            mock_log.assert_called_once_with("Unexpected error during token validation: oops")


# ------------------------------------------------------------
# Tests for require_api_key
# ------------------------------------------------------------
class TestRequireApiKey:
    @pytest.fixture(autouse=True)
    def setup_settings(self):
        with patch.object(settings, "PIPELINE_API_KEY", "secretkey"):
            yield

    def test_missing_api_key(self):
        decorated = require_api_key(dummy_view)
        with app.test_request_context():
            response, status = decorated()
            assert status == 401
            assert b"Missing API key" in response.data

    def test_invalid_api_key(self):
        decorated = require_api_key(dummy_view)
        with app.test_request_context(headers={"X-API-Key": "wrongkey"}, environ_base={"REMOTE_ADDR": "127.0.0.1"}), \
             patch("devsecops_radar.core.auth.hmac.compare_digest", return_value=False), \
             patch.object(logger, "warning") as mock_warning:
            response, status = decorated()
            assert status == 401
            assert b"Invalid API key." in response.data
            mock_warning.assert_called_once_with("Invalid API key attempt from IP: 127.0.0.1")

    def test_valid_api_key(self):
        decorated = require_api_key(dummy_view)
        with app.test_request_context(headers={"X-API-Key": "secretkey"}), \
             patch("devsecops_radar.core.auth.hmac.compare_digest", return_value=True):
            # Successful authentication returns the view result directly
            response = decorated()
            assert response.status_code == 200
            assert b'"data":"ok"' in response.data
