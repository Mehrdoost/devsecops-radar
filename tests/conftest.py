import os
import sys
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Prevent PyO3/cryptography errors in test environment
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
def _clear_rate_limits():
    """Reset the in‑memory rate‑limiter store before each test."""
    try:
        from devsecops_radar.web.app import _rate_store
        _rate_store.clear()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _disable_rate_limiting(monkeypatch):
    """Make the rate_limited decorator a no‑op so no test ever gets 429."""
    try:
        from devsecops_radar.web import app as web_app
        monkeypatch.setattr(
            web_app,
            "rate_limited",
            lambda *a, **kw: lambda f: f,
        )
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _patch_settings_api_key(monkeypatch):
    """Force the settings singleton to use the test API key."""
    from devsecops_radar.core.settings import settings
    monkeypatch.setattr(settings, "PIPELINE_API_KEY", "test-api-key")
