import os
import sys
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Prevent PyO3/cryptography errors in test environment by mocking before
# any module that might try to import them.
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
