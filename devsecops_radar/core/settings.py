import os

from dotenv import load_dotenv
from loguru import logger

# Load environment variables from .env file if it exists
load_dotenv()

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
            logger.error(f"Invalid PORT configuration: '{value}'. Must be an integer between 1 and 65535.")
            raise ValueError(f"Invalid PORT: {value}") from None

    @staticmethod
    def _validate_jwt_secret() -> str:
        """Ensure JWT_SECRET is present and secure."""
        secret = os.environ.get("JWT_SECRET")
        if not secret:
            logger.error("Critical Security Error: JWT_SECRET environment variable is missing.")
            raise ValueError("JWT_SECRET environment variable is required for secure operation.")
        if len(secret) < 32:
            logger.error("Critical Security Error: JWT_SECRET is too short. Minimum 32 characters required.")
            raise ValueError("JWT_SECRET must be at least 32 characters long.")
        return secret

    @staticmethod
    def _validate_api_key() -> str:
        """Ensure API Key is explicitly set. No dangerous defaults."""
        api_key = os.environ.get("PIPELINE_API_KEY")
        if not api_key:
            logger.error("Critical Security Error: PIPELINE_API_KEY environment variable is missing.")
            raise ValueError("PIPELINE_API_KEY environment variable is required.")

        # Prevent the user from explicitly typing "disabled" to bypass auth
        if api_key.strip().lower() == "disabled":
            logger.error("Critical Security Error: PIPELINE_API_KEY cannot be set to 'disabled'.")
            raise ValueError("PIPELINE_API_KEY value 'disabled' is strictly prohibited.")
        return api_key

# Instantiate settings singleton.
# If validation fails, the app will explicitly crash here at import time (Fail-Fast).
try:
    settings = Settings()
except ValueError as e:
    raise RuntimeError(f"Configuration Initialization Failed: {e}") from e
