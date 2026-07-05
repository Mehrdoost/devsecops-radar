"""Complete tests for the Settings configuration class.

Covers all properties, lazy secret validation, optional URL validators,
Ollama base URL handling, community rules repo parsing, port parsing,
boolean parsing, and extra trusted binary directories.
"""

from __future__ import annotations

import pytest

from devsecops_radar.core.settings import Settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove all relevant env vars to start fresh."""
    for var in (
        "JWT_SECRET",
        "PIPELINE_API_KEY",
        "HOST",
        "PORT",
        "DEBUG",
        "JIRA_URL",
        "JIRA_TOKEN",
        "JIRA_PROJECT_KEY",
        "JIRA_ISSUE_TYPE",
        "ASANA_TOKEN",
        "ASANA_WORKSPACE",
        "COMMUNITY_RULES_REPO",
        "OLLAMA_API_BASE",
        "EXTRA_TRUSTED_BIN_DIRS",
    ):
        monkeypatch.delenv(var, raising=False)


class TestNonCriticalSettings:
    """Verify default values and parsers for non‑secret configs."""

    def test_default_host_and_port(self, clean_env: None) -> None:
        s = Settings()
        assert s.HOST == "127.0.0.1"
        assert s.PORT == 8080

    def test_custom_host_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOST", "0.0.0.0")
        monkeypatch.setenv("PORT", "3000")
        s = Settings()
        assert s.HOST == "0.0.0.0"
        assert s.PORT == 3000

    def test_invalid_port_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PORT", "99999")
        with pytest.raises(ValueError, match="Invalid PORT"):
            Settings()

    def test_port_zero_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PORT", "0")
        with pytest.raises(ValueError, match="Invalid PORT"):
            Settings()

    def test_debug_true_variants(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for val in ("true", "1", "t", "yes", "y", "on", "TRUE"):
            monkeypatch.setenv("DEBUG", val)
            s = Settings()
            assert s.DEBUG is True

    def test_debug_false_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DEBUG", raising=False)
        s = Settings()
        assert s.DEBUG is False


class TestValidateJwtSecret:
    """Lazy JWT_SECRET property tests (ValueError on access)."""

    def test_valid_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET", "a" * 64)
        s = Settings()
        # Access triggers validation, no exception
        assert s.JWT_SECRET == "a" * 64

    def test_missing_secret_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("JWT_SECRET", raising=False)
        s = Settings()
        with pytest.raises(ValueError, match="JWT_SECRET environment variable is required"):
            _ = s.JWT_SECRET

    def test_secret_too_short_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET", "short")
        s = Settings()
        with pytest.raises(ValueError, match="at least 64 characters"):
            _ = s.JWT_SECRET

    def test_low_entropy_warning_logged(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Low entropy triggers a warning but does not raise."""
        monkeypatch.setenv("JWT_SECRET", "a" * 64)
        s = Settings()
        _ = s.JWT_SECRET
        # Check that the loguru warning was captured via caplog
        assert any("low entropy" in record.message.lower() for record in caplog.records)


class TestValidateApiKey:
    """Lazy PIPELINE_API_KEY property tests."""

    def test_valid_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PIPELINE_API_KEY", "x" * 20)
        s = Settings()
        assert s.PIPELINE_API_KEY == "x" * 20

    def test_missing_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PIPELINE_API_KEY", raising=False)
        s = Settings()
        with pytest.raises(ValueError, match="PIPELINE_API_KEY environment variable is required"):
            _ = s.PIPELINE_API_KEY

    def test_disabled_value_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PIPELINE_API_KEY", "disabled")
        s = Settings()
        with pytest.raises(ValueError, match="strictly prohibited"):
            _ = s.PIPELINE_API_KEY

    def test_key_too_short_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PIPELINE_API_KEY", "short")
        s = Settings()
        with pytest.raises(ValueError, match="at least 20 characters"):
            _ = s.PIPELINE_API_KEY


class TestOptionalUrlValidators:
    """Tests for Jira URL, OLLAMA_API_BASE, and community repo validators."""

    def test_jira_url_valid_https(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
        s = Settings()
        assert s.JIRA_URL == "https://jira.example.com"

    def test_jira_url_valid_http_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_validate_optional_url accepts both http and https."""
        monkeypatch.setenv("JIRA_URL", "http://jira.example.com")
        s = Settings()
        # The code allows http, so it is stored.
        assert s.JIRA_URL == "http://jira.example.com"

    def test_jira_url_invalid_scheme_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JIRA_URL", "ftp://jira.example.com")
        s = Settings()
        assert s.JIRA_URL is None

    def test_jira_url_no_host_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JIRA_URL", "https:///path")
        s = Settings()
        assert s.JIRA_URL is None

    def test_jira_url_strips_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JIRA_URL", "https://user:pass@jira.example.com")
        s = Settings()
        assert s.JIRA_URL == "https://jira.example.com"

    def test_ollama_api_base_default(self, clean_env: None) -> None:
        s = Settings()
        assert s.OLLAMA_API_BASE == "http://localhost:11434/api/generate"

    def test_ollama_custom_base(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OLLAMA_API_BASE", "http://my-ollama:8080")
        s = Settings()
        assert s.OLLAMA_API_BASE == "http://my-ollama:8080/api/generate"

    def test_ollama_strips_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OLLAMA_API_BASE", "http://user:pass@localhost:11434")
        s = Settings()
        assert s.OLLAMA_API_BASE == "http://localhost:11434/api/generate"

    def test_ollama_invalid_scheme_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OLLAMA_API_BASE", "ftp://bad")
        s = Settings()
        assert s.OLLAMA_API_BASE == "http://localhost:11434/api/generate"

    def test_community_rules_repo_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMMUNITY_RULES_REPO", "https://github.com/user/repo.git")
        s = Settings()
        assert s.COMMUNITY_RULES_REPO == "https://github.com/user/repo.git"

    def test_community_repo_invalid_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMMUNITY_RULES_REPO", "ftp://example.com/repo.git")
        s = Settings()
        assert s.COMMUNITY_RULES_REPO is None

    def test_community_repo_missing_dot_git(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMMUNITY_RULES_REPO", "https://example.com/repo")
        s = Settings()
        assert s.COMMUNITY_RULES_REPO is None

    def test_community_repo_invalid_characters(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMMUNITY_RULES_REPO", "https://example.com/repo.git;rm -rf /")
        s = Settings()
        assert s.COMMUNITY_RULES_REPO is None

    def test_community_repo_strips_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMMUNITY_RULES_REPO", "https://user:pass@github.com/user/repo.git")
        s = Settings()
        assert s.COMMUNITY_RULES_REPO == "https://github.com/user/repo.git"


class TestAsanaWorkspaceValidation:
    """Validate Asana workspace GID parsing."""

    def test_valid_workspace(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ASANA_WORKSPACE", "123456789")
        s = Settings()
        assert s.ASANA_WORKSPACE == "123456789"

    def test_non_numeric_workspace_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ASANA_WORKSPACE", "abc")
        s = Settings()
        assert s.ASANA_WORKSPACE is None


class TestExtraTrustedBinDirs:
    """Ensure extra trusted binary directories are parsed correctly."""

    def test_empty_by_default(self, clean_env: None) -> None:
        s = Settings()
        assert s.EXTRA_TRUSTED_BIN_DIRS == []

    def test_single_dir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EXTRA_TRUSTED_BIN_DIRS", "/opt/custom")
        s = Settings()
        assert s.EXTRA_TRUSTED_BIN_DIRS == ["/opt/custom"]

    def test_multiple_dirs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EXTRA_TRUSTED_BIN_DIRS", "/opt/a, /opt/b , /opt/c")
        s = Settings()
        assert s.EXTRA_TRUSTED_BIN_DIRS == ["/opt/a", "/opt/b", "/opt/c"]
