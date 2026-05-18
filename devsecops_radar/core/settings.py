import os
import secrets

class Settings:
    JWT_SECRET: str = os.environ.get("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24
    PIPELINE_API_KEY: str = os.environ.get("PIPELINE_API_KEY", "disabled")
    DEBUG: bool = os.environ.get("DEBUG", "false").lower() == "true"
    HOST: str = os.environ.get("HOST", "127.0.0.1")
    PORT: int = int(os.environ.get("PORT", "8080"))

    def __init__(self):
        if not self.JWT_SECRET:
            self.JWT_SECRET = secrets.token_hex(32)
            print("WARNING: JWT_SECRET not set. Using temporary secret:", self.JWT_SECRET)
            print("Set the JWT_SECRET environment variable for production use.")

settings = Settings()