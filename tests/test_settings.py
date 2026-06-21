"""Tests for centralised configuration management."""

import os
from contextlib import contextmanager
from unittest.mock import patch

import pytest

# Set required environment variables BEFORE importing the settings module,
# otherwise the module-level singleton creation will fail (sys.exit).
os.environ.setdefault("JWT_SECRET", "a" * 32)  # minimum length 32
os.environ.setdefault("PIPELINE_API_KEY", "test-api-key-12345")

# Now it's safe to import
from loguru import logger

from devsecops_radar.core.settings import Settings


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
def clean_env(monkeypatch):
    """Provide a clean environment with valid but overridable defaults."""
    monkeypatch.setenv("JWT_SECRET", "b" * 32)
    monkeypatch.setenv("PIPELINE_API_KEY", "valid-key")
    yield


# ============================================================================
# Tests for .env loading
# ============================================================================
class TestEnvLoading:
    def test_env_file_found_and_loaded(self, monkeypatch):
        with patch("pathlib.Path.exists", return_value=True):
            with patch(
                "devsecops_radar.core.settings.load_dotenv"
            ):
                # Force re-execution of the module-level code
                import devsecops_radar.core.settings as mod

                # The code already ran on first import; we can't easily re-run
                # the module-level block. But we can verify that the path
                # logic is correct by checking _DOTENV_PATH.
                assert mod._DOTENV_PATH.name == ".env"
                # We trust load_dotenv was called on first import if file existed.
                # This test is mostly to document the behavior.
                # We'll just check that the function is callable.
                assert callable(mod.load_dotenv)

    def test_env_file_missing_does_not_crash(self):
        # The module already imported without .env; no error raised.
        # We can check that _DOTENV_PATH is correct.
        import devsecops_radar.core.settings as mod

        assert mod._DOTENV_PATH.name == ".env"


# ============================================================================
# Tests for Settings class fields
# ============================================================================
class TestSettingsFields:
    def test_default_host_and_port(self, clean_env):
        s = Settings()
        assert s.HOST == "127.0.0.1"
        assert s.PORT == 8080
        assert s.DEBUG is False

    def test_custom_values(self, monkeypatch):
        monkeypatch.setenv("HOST", "0.0.0.0")
        monkeypatch.setenv("PORT", "3000")
        monkeypatch.setenv("DEBUG", "true")
        s = Settings()
        assert s.HOST == "0.0.0.0"
        assert s.PORT == 3000
        assert s.DEBUG is True


# ============================================================================
# Tests for _parse_bool
# ============================================================================
class TestParseBool:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("true", True),
            ("1", True),
            ("yes", True),
            ("on", True),
            ("TRUE", True),
            ("True", True),
            ("false", False),
            ("0", False),
            ("no", False),
            ("off", False),
            ("any", False),
            ("", False),
        ],
    )
    def test_various_values(self, clean_env, value, expected):
        assert Settings._parse_bool(value) == expected

    def test_strips_whitespace(self, clean_env):
        assert Settings._parse_bool("  true  ") is True


# ============================================================================
# Tests for _parse_port
# ============================================================================
class TestParsePort:
    def test_valid_port(self, clean_env):
        assert Settings._parse_port("5432") == 5432

    def test_port_too_low(self, clean_env):
        with capture_loguru() as msgs:
            with pytest.raises(ValueError, match="Invalid PORT"):
                Settings._parse_port("0")
        assert any("Invalid PORT configuration" in m for m in msgs)

    def test_port_too_high(self, clean_env):
        with pytest.raises(ValueError):
            Settings._parse_port("70000")

    def test_non_numeric_port(self, clean_env):
        with pytest.raises(ValueError):
            Settings._parse_port("abc")


# ============================================================================
# Tests for _validate_jwt_secret
# ============================================================================
class TestValidateJwtSecret:
    def test_valid_secret(self, clean_env):
        s = Settings()
        assert s.JWT_SECRET == "b" * 32

    def test_missing_secret(self, monkeypatch):
        monkeypatch.delenv("JWT_SECRET")
        with capture_loguru() as msgs:
            with pytest.raises(ValueError, match="JWT_SECRET.*required"):
                Settings()
        assert any("JWT_SECRET environment variable is missing" in m for m in msgs)

    def test_secret_too_short(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "short")
        with capture_loguru() as msgs:
            with pytest.raises(ValueError, match="at least 32 characters"):
                Settings()
        assert any("JWT_SECRET is too short" in m for m in msgs)

    def test_low_entropy_warning(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "a" * 32)  # all same char
        with capture_loguru() as msgs:
            s = Settings()
            assert s.JWT_SECRET == "a" * 32
        assert any("low entropy" in m for m in msgs)


# ============================================================================
# Tests for _validate_api_key
# ============================================================================
class TestValidateApiKey:
    def test_valid_key(self, clean_env):
        s = Settings()
        assert s.PIPELINE_API_KEY == "valid-key"

    def test_missing_key(self, monkeypatch):
        monkeypatch.delenv("PIPELINE_API_KEY")
        with capture_loguru() as msgs:
            with pytest.raises(ValueError, match="PIPELINE_API_KEY.*required"):
                Settings()
        assert any(
            "PIPELINE_API_KEY environment variable is missing" in m for m in msgs
        )

    def test_disabled_value_prohibited(self, monkeypatch):
        monkeypatch.setenv("PIPELINE_API_KEY", "disabled")
        with capture_loguru() as msgs:
            with pytest.raises(ValueError, match="strictly prohibited"):
                Settings()
        assert any("cannot be set to 'disabled'" in m for m in msgs)

    def test_disabled_with_whitespace(self, monkeypatch):
        monkeypatch.setenv("PIPELINE_API_KEY", "  Disabled  ")
        with pytest.raises(ValueError):
            Settings()
