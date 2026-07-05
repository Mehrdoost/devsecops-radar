# devsecops_radar/core/settings.py
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from loguru import logger

# ---------------------------------------------------------------------------
# Load .env from the **current working directory** (where the user runs the app)
# ---------------------------------------------------------------------------
_DOTENV_PATH = Path.cwd() / ".env"
if _DOTENV_PATH.exists():
    load_dotenv(_DOTENV_PATH)
else:
    logger.debug("No .env file found in current directory; relying on environment variables.")


class Settings:
    """Centralized configuration management for Pipeline Sentinel.

    Mandatory secrets (JWT_SECRET, PIPELINE_API_KEY) are validated lazily
    when first accessed – this prevents fail‑fast crashes on ``import`` and
    allows ``--help`` to work without a configured environment.
    """

    def __init__(self) -> None:
        # Non‑critical settings (always safe to read)
        self.HOST: str = os.environ.get("HOST", "127.0.0.1")
        self.PORT: int = self._parse_port(os.environ.get("PORT", "8080"))
        self.DEBUG: bool = self._parse_bool(os.environ.get("DEBUG", "false"))

        # External service settings – validated when accessed
        self.JIRA_URL: str | None = self._validate_optional_url(
            os.environ.get("JIRA_URL"), "JIRA_URL"
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

        # Extra trusted binary directories (for utils.py)
        self.EXTRA_TRUSTED_BIN_DIRS: list[str] = [
            d.strip()
            for d in os.environ.get("EXTRA_TRUSTED_BIN_DIRS", "").split(",")
            if d.strip()
        ]

        # Lazy secret holders – validated on first access
        self._jwt_secret: str | None = None
        self._pipeline_api_key: str | None = None

    # ------------------------------------------------------------------
    # Lazy properties for mandatory secrets
    # ------------------------------------------------------------------
    @property
    def JWT_SECRET(self) -> str:     # noqa: N802
        if self._jwt_secret is None:
            self._jwt_secret = self._validate_jwt_secret()
        return self._jwt_secret

    @property
    def PIPELINE_API_KEY(self) -> str:   # noqa: N802
        if self._pipeline_api_key is None:
            self._pipeline_api_key = self._validate_api_key()
        return self._pipeline_api_key

    # ------------------------------------------------------------------
    # Parsing helpers
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
    # Security‑critical validators (lazy, called from properties)
    # ------------------------------------------------------------------
    @staticmethod
    def _validate_jwt_secret() -> str:
        secret = os.environ.get("JWT_SECRET", "").strip()
        if not secret:
            raise ValueError(
                "JWT_SECRET environment variable is required. "
                "Please set a cryptographically strong secret."
            )
        if len(secret) < 64:
            raise ValueError(
                "JWT_SECRET must be at least 64 characters (32 bytes hex). "
                "Use: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        # Simple heuristic warning, but never blocks
        if len(set(secret)) < 10:
            logger.warning(
                "JWT_SECRET has very low entropy. Consider using a "
                "cryptographically random string (e.g. secrets.token_hex(32))."
            )
        return secret

    @staticmethod
    def _validate_api_key() -> str:
        api_key = os.environ.get("PIPELINE_API_KEY", "").strip()
        if not api_key:
            raise ValueError(
                "PIPELINE_API_KEY environment variable is required."
            )
        if api_key.lower() == "disabled":
            raise ValueError(
                "PIPELINE_API_KEY value 'disabled' is strictly prohibited."
            )
        if len(api_key) < 20:
            raise ValueError(
                "PIPELINE_API_KEY must be at least 20 characters."
            )
        return api_key

    # ------------------------------------------------------------------
    # URL validators (with credential stripping – safe logging)
    # ------------------------------------------------------------------
    @staticmethod
    def _strip_url_credentials(parsed) -> str:
        """Return the URL without username:password, and log a generic warning."""
        if parsed.username or parsed.password:
            logger.warning(
                "URL contains embedded credentials – they have been stripped "
                "to prevent accidental leakage."
            )
        return parsed._replace(
            netloc=parsed.hostname + (f":{parsed.port}" if parsed.port else "")
        ).geturl()

    @staticmethod
    def _validate_jira_url(value: str | None) -> str | None:
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
            safe_url = Settings._strip_url_credentials(parsed)
            return safe_url.rstrip("/")
        except Exception:
            logger.warning("Invalid JIRA_URL, ignoring.")
            return None

    @staticmethod
    def _validate_community_repo(value: str | None) -> str | None:
        """Accept any HTTPS git repository (not just github.com)."""
        if not value:
            return None
        value = value.strip()
        try:
            parsed = urlparse(value)
            if parsed.scheme != "https":
                logger.error(
                    "COMMUNITY_RULES_REPO must be an HTTPS URL. "
                    "Value ignored."
                )
                return None
            if not value.endswith(".git"):
                logger.error(
                    "COMMUNITY_RULES_REPO must end with '.git'. "
                    "Value ignored."
                )
                return None
            # Only allow safe characters in the URL (prevent injection)
            if not re.match(r"^[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;%=]+$", value):
                logger.error(
                    "COMMUNITY_RULES_REPO contains invalid characters. "
                    "Value ignored."
                )
                return None
            safe_url = Settings._strip_url_credentials(parsed)
            return safe_url.rstrip("/")
        except Exception:
            logger.warning("Invalid COMMUNITY_RULES_REPO, ignoring.")
            return None

    @staticmethod
    def _validate_ollama_base(raw: str) -> str:
        raw = raw.strip().rstrip("/")
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            logger.warning("Invalid OLLAMA_API_BASE scheme. Falling back to localhost.")
            return "http://localhost:11434/api/generate"
        safe = Settings._strip_url_credentials(parsed)
        if not safe.endswith("/api/generate"):
            safe = safe.rstrip("/") + "/api/generate"
        return safe

    @staticmethod
    def _validate_optional_url(value: str | None, name: str) -> str | None:
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
            safe_url = Settings._strip_url_credentials(parsed)
            return safe_url.rstrip("/")
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
# Global instance – no fail‑fast, secrets are lazy
# ------------------------------------------------------------------
settings = Settings()
