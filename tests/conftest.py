import os

# Ensure that JWT_SECRET and PIPELINE_API_KEY are set before any application imports
# This runs before the test collection, preventing the Fail-Fast from triggering.

os.environ.setdefault("JWT_SECRET", "test-jwt-secret-for-ci-at-least-32chars!")
os.environ.setdefault("PIPELINE_API_KEY", "test-api-key-for-ci-at-least-32chars!")

# Also set DEBUG to avoid production WSGI
os.environ.setdefault("DEBUG", "true")

# If you use HOST/PORT, you can set them too
os.environ.setdefault("HOST", "127.0.0.1")
os.environ.setdefault("PORT", "8080")
