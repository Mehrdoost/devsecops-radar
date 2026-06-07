import os

os.environ.setdefault("JWT_SECRET", "test-jwt-secret-with-sufficient-length")
os.environ.setdefault("PIPELINE_API_KEY", "test-api-key")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")