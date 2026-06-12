import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from loguru import logger

# Locate .env relative to the project root (three levels up from this file)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DOTENV_PATH = _PROJECT_ROOT / ".env"

# Only load from the expected project root – never from the current working directory
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

    @staticmethod
    def _parse_bool(value: str) -> bool:
        """Parse boolean values safely, avoiding deprecated distutils."""
        truthy: set[str] = {"true", "1", "t", "yes", "y", "on"}
        return value.strip().lower() in truthy

    @staticmethod
    def _parse_port(value: str) -> int:
        """Parse and validate the port number."""
        try:
            port = int(value)
            if not (1 <= port <= 65535):
                raise ValueError
            return port
        except ValueError:
            logger.error(
                f"Invalid PORT configuration: '{value}'. "
                "Must be an integer between 1 and 65535."
            )
            raise ValueError(f"Invalid PORT: {value}") from None

    @staticmethod
    def _validate_jwt_secret() -> str:
        """Ensure JWT_SECRET is present, secure, and not left as a default example."""
        secret = os.environ.get("JWT_SECRET")
        if not secret:
            logger.error(
                "Critical Security Error: JWT_SECRET environment variable is missing."
            )
            raise ValueError(
                "JWT_SECRET environment variable is required for secure operation."
            )
        if len(secret) < 32:
            logger.error(
                "Critical Security Error: JWT_SECRET is too short. "
                "Minimum 32 characters required."
            )
            raise ValueError("JWT_SECRET must be at least 32 characters long.")
        # Optional: warn about low entropy (e.g. all same character)
        if len(set(secret)) < 4:
            logger.warning(
                "JWT_SECRET has very low entropy. Consider using a stronger secret."
            )
        return secret

    @staticmethod
    def _validate_api_key() -> str:
        """Ensure API Key is explicitly set. No dangerous defaults."""
        api_key = os.environ.get("PIPELINE_API_KEY")
        if not api_key:
            logger.error(
                "Critical Security Error: PIPELINE_API_KEY environment variable "
                "is missing."
            )
            raise ValueError(
                "PIPELINE_API_KEY environment variable is required."
            )

        # Prevent the user from explicitly typing "disabled" to bypass auth
        if api_key.strip().lower() == "disabled":
            logger.error(
                "Critical Security Error: PIPELINE_API_KEY cannot be set to "
                "'disabled'."
            )
            raise ValueError(
                "PIPELINE_API_KEY value 'disabled' is strictly prohibited."
            )
        return api_key


# Instantiate settings singleton with friendly error message.
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
    print("  The file must include JWT_SECRET and PIPELINE_API_KEY.")
    print("=" * 60 + "\n")
    sys.exit(1)
