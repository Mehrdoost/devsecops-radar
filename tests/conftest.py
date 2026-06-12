import os
import sys
import types
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Prevent PyO3/cryptography errors by mocking the dependency tree before
# any other module tries to import it.
# ---------------------------------------------------------------------------
for mod in (
    "cryptography",
    "cryptography.hazmat",
    "cryptography.hazmat.bindings",
    "cryptography.hazmat.bindings._rust",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.asymmetric",
    "cryptography.hazmat.primitives.asymmetric.ec",
):
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

# ---------------------------------------------------------------------------
# Build a minimal fake `jwt` module that provides the real exception classes
# and both `encode` / `decode` functions so that tests can patch them.
# ---------------------------------------------------------------------------
if "jwt" not in sys.modules:
    _fake_jwt = types.ModuleType("jwt")

    class PyJWTError(Exception):
        pass

    class ExpiredSignatureError(PyJWTError):
        pass

    class InvalidTokenError(PyJWTError):
        pass

    def encode(payload, key, algorithm="HS256", **kwargs):
        # Will be mocked in individual tests.
        raise NotImplementedError("jwt.encode is mocked – use patch in tests")

    def decode(token, key, algorithms=None, **kwargs):
        # Will be mocked in individual tests.
        raise NotImplementedError("jwt.decode is mocked – use patch in tests")

    _fake_jwt.PyJWTError = PyJWTError
    _fake_jwt.ExpiredSignatureError = ExpiredSignatureError
    _fake_jwt.InvalidTokenError = InvalidTokenError
    _fake_jwt.encode = encode
    _fake_jwt.decode = decode

    sys.modules["jwt"] = _fake_jwt

# ---------------------------------------------------------------------------
# Environment defaults – MUST be set before any project module is imported.
# ---------------------------------------------------------------------------
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-with-sufficient-length")
os.environ.setdefault("PIPELINE_API_KEY", "test-api-key")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

# ---------------------------------------------------------------------------
# Fixtures that run automatically before every test
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_rate_limits(monkeypatch):
    """Reset in‑memory rate‑limiter stores before each test."""
    from devsecops_radar.core.auth import _rate_limit_store as auth_store
    auth_store.clear()

    try:
        from devsecops_radar.web.app import _login_rate_store as login_store
        login_store.clear()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _patch_settings_api_key(monkeypatch):
    """Force the settings singleton to use the test API key."""
    from devsecops_radar.core.settings import settings
    monkeypatch.setattr(settings, "PIPELINE_API_KEY", "test-api-key")