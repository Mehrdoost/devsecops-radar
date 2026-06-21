# devsecops_radar/core/settings.py
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from loguru import logger

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DOTENV_PATH = _PROJECT_ROOT / ".env"

if _DOTENV_PATH.exists():
    load_dotenv(_DOTENV_PATH)
else:
    logger.debug("No .env file found in project root; relying on environment variables.")


class Settings:
    """Centralized configuration management for Pipeline Sentinel."""

    def __init__(self) -> None:
        self.HOST: str = os.environ.get("HOST", "127.0.0.1")
        self.PORT: int = self._parse_port(os.environ.get("PORT", "8080"))
        self.DEBUG: bool = self._parse_bool(os.environ.get("DEBUG", "false"))

        self.JWT_SECRET: str = self._validate_jwt_secret()
        self.PIPELINE_API_KEY: str = self._validate_api_key()

        # External service settings – now aligned with notifier expectations
        self.JIRA_URL: str | None = self._validate_jira_url(
            os.environ.get("JIRA_URL")
        )
        self.JIRA_TOKEN: str | None = os.environ.get("JIRA_TOKEN") or None
        self.JIRA_PROJECT_KEY: str = os.environ.get("JIRA_PROJECT_KEY", "SEC")
        self.JIRA_ISSUE_TYPE: str = os.environ.get("JIRA_ISSUE_TYPE", "Bug")

        self.ASANA_TOKEN: str | None = os.environ.get("ASANA_TOKEN") or None
        self.ASANA_WORKSPACE: str | None = self._validate_workspace_gid(
            os.environ.get("ASANA_WORKSPACE")
        )

        self.COMMUNITY_RULES_REPO: str | None = self._validate_community_repo(
            os.environ.get("COMMUNITY_RULES_REPO")
        )

        self.OLLAMA_API_BASE: str = self._validate_ollama_base(
            os.environ.get("OLLAMA_API_BASE", "http://localhost:11434")
        )

    # ------------------------------------------------------------------
    # Parsing helpers (unchanged)
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_bool(value: str) -> bool:
        truthy: set[str] = {"true", "1", "t", "yes", "y", "on"}
        return value.strip().lower() in truthy

    @staticmethod
    def _parse_port(value: str) -> int:
        try:
            port = int(value)
            if not 1 <= port <= 65535:
                raise ValueError
            return port
        except ValueError:
            logger.error(
                f"Invalid PORT configuration: '{value}'. "
                "Must be an integer between 1 and 65535."
            )
            raise ValueError(f"Invalid PORT: {value}") from None

    # ------------------------------------------------------------------
    # Security‑critical validators (JWT, API key)
    # ------------------------------------------------------------------
    @staticmethod
    def _validate_jwt_secret() -> str:
        secret = os.environ.get("JWT_SECRET")
        if not secret:
            logger.error(
                "Critical Security Error: JWT_SECRET environment variable is missing."
            )
            raise ValueError("JWT_SECRET environment variable is required.")
        if len(secret) < 32:
            logger.error(
                "Critical Security Error: JWT_SECRET is too short. "
                "Minimum 32 characters required."
            )
            raise ValueError("JWT_SECRET must be at least 32 characters long.")
        if len(set(secret)) < 6:
            logger.warning(
                "JWT_SECRET has very low entropy. Consider using a cryptographically "
                "random string (e.g. openssl rand -hex 32)."
            )
        return secret

    @staticmethod
    def _validate_api_key() -> str:
        api_key = os.environ.get("PIPELINE_API_KEY")
        if not api_key:
            logger.error(
                "Critical Security Error: PIPELINE_API_KEY environment variable is missing."
            )
            raise ValueError("PIPELINE_API_KEY environment variable is required.")
        if api_key.strip().lower() == "disabled":
            logger.error(
                "Critical Security Error: PIPELINE_API_KEY cannot be set to 'disabled'."
            )
            raise ValueError("PIPELINE_API_KEY value 'disabled' is strictly prohibited.")
        return api_key

    # ------------------------------------------------------------------
    # URL validators (now consistent with downstream consumers)
    # ------------------------------------------------------------------
    @staticmethod
    def _validate_jira_url(value: str | None) -> str | None:
        """Jira URL must be HTTPS – enforced identically in notifier.py."""
        if not value:
            return None
        try:
            parsed = urlparse(value.strip())
            if parsed.scheme != "https":
                logger.error("JIRA_URL must use HTTPS. Value ignored.")
                return None
            if not parsed.netloc:
                logger.error("JIRA_URL has no hostname. Value ignored.")
                return None
            return value.strip().rstrip("/")
        except Exception:
            logger.warning("Invalid JIRA_URL, ignoring.")
            return None

    @staticmethod
    def _validate_community_repo(value: str | None) -> str | None:
        """Community rules repo – only https://github.com is allowed."""
        if not value:
            return None
        try:
            parsed = urlparse(value.strip())
            if parsed.scheme != "https" or parsed.netloc != "github.com":
                logger.error(
                    "COMMUNITY_RULES_REPO must be a https://github.com URL. "
                    "Value ignored."
                )
                return None
            if not value.strip().endswith(".git") or ";" in value or " " in value:
                logger.error("COMMUNITY_RULES_REPO contains invalid characters.")
                return None
            return value.strip().rstrip("/")
        except Exception:
            logger.warning("Invalid COMMUNITY_RULES_REPO, ignoring.")
            return None

    @staticmethod
    def _validate_ollama_base(raw: str) -> str:
        """Ensure OLLAMA_API_BASE ends with /api/generate."""
        raw = raw.strip().rstrip("/")
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            logger.warning("Invalid OLLAMA_API_BASE scheme. Falling back to localhost.")
            return "http://localhost:11434/api/generate"
        # Append the API path if the user only gave a base URL
        if not raw.endswith("/api/generate"):
            return f"{raw}/api/generate"
        return raw

    @staticmethod
    def _validate_optional_url(value: str | None, name: str) -> str | None:
        """Generic optional URL validator – allows http/https."""
        if not value:
            return None
        try:
            parsed = urlparse(value.strip())
            if parsed.scheme not in ("https", "http"):
                logger.warning(f"{name} has invalid scheme, ignoring.")
                return None
            if not parsed.netloc:
                logger.warning(f"{name} has no hostname, ignoring.")
                return None
            return value.strip().rstrip("/")
        except Exception:
            logger.warning(f"Invalid {name} URL, ignoring.")
            return None

    @staticmethod
    def _validate_workspace_gid(value: str | None) -> str | None:
        if not value:
            return None
        if not re.match(r"^\d+$", value.strip()):
            logger.error("ASANA_WORKSPACE must be a numeric GID. Ignoring.")
            return None
        return value.strip()


# ------------------------------------------------------------------
# Fail‑fast instantiation
# ------------------------------------------------------------------
try:
    settings = Settings()
except ValueError as e:
    print("\n" + "=" * 60)
    print("  🚨  Pipeline Sentinel – Configuration Error  🚨")
    print("=" * 60)
    print(f"  {e}")
    print(
        "  Please create a .env file in the project root using .env.example "
        "as a template."
    )
    print("  The file must include JWT_SECRET and PIPELINE_API_KEY."
    )
    print("=" * 60 + "\n")
    sys.exit(1)
