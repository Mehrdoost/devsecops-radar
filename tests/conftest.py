# tests/conftest.py (mypy‑clean)
import logging
import os
import sys
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest
from _pytest.monkeypatch import MonkeyPatch

for _mod in (
    "cryptography",
    "cryptography.hazmat",
    "cryptography.hazmat.bindings",
    "cryptography.hazmat.bindings._rust",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.asymmetric",
    "cryptography.hazmat.primitives.asymmetric.ec",
):
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

os.environ.setdefault("JWT_SECRET", "a" * 64)
os.environ.setdefault("PIPELINE_API_KEY", "x" * 20)
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")


class _LoguruHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        logger = logging.getLogger(record.name)
        logger.handle(record)


@pytest.fixture(autouse=True)
def _integrate_loguru_with_caplog(
    caplog: pytest.LogCaptureFixture,
) -> Generator[None, None, None]:
    from loguru import logger

    handler_id = logger.add(
        _LoguruHandler(),
        level="DEBUG",
        format="{message}",
        catch=True,
    )
    yield
    try:
        logger.remove(handler_id)
    except ValueError:
        pass


@pytest.fixture(autouse=True)
def _clear_rate_limits() -> None:
    try:
        from devsecops_radar.core.auth import _rate_store
        _rate_store.clear()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _patch_settings_private_fields() -> None:
    from devsecops_radar.core.settings import settings
    settings._pipeline_api_key = "x" * 20
    settings._jwt_secret = "a" * 64


@pytest.fixture(autouse=True)
def _auto_auth_headers(monkeypatch: MonkeyPatch) -> None:
    import flask

    original_test_client = flask.Flask.test_client

    def _patched_test_client(app, *args: Any, **kwargs: Any):
        client = original_test_client(app, *args, **kwargs)
        original_open = client.open

        def _patched_open(*open_args: Any, **open_kwargs: Any):
            headers = open_kwargs.setdefault("headers", {})
            if isinstance(headers, dict):
                headers.setdefault("X-API-Key", "x" * 20)
            elif isinstance(headers, list):
                headers.append(("X-API-Key", "x" * 20))
            return original_open(*open_args, **open_kwargs)

        # mypy: allow assigning to method for monkeypatching
        client.open = _patched_open  # type: ignore[method-assign]
        return client

    monkeypatch.setattr(flask.Flask, "test_client", _patched_test_client)
