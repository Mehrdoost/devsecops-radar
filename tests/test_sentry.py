"""Tests for the live sentry feed endpoints."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask.testing import FlaskClient

from devsecops_radar.core.database import init_db
from devsecops_radar.web.app import create_app


@pytest.fixture
def app() -> Flask:
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


@pytest.fixture(autouse=True)
def _init_db() -> None:
    init_db()


class TestReceiveScan:
    def test_missing_content_type(self, client: FlaskClient) -> None:
        resp = client.post("/api/scan-result")
        assert resp.status_code == 400

    def test_malformed_json(self, client: FlaskClient) -> None:
        resp = client.post(
            "/api/scan-result",
            data="not json",
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_non_dict_payload(self, client: FlaskClient) -> None:
        resp = client.post("/api/scan-result", json=[])
        assert resp.status_code == 400

    def test_payload_too_large(self, client: FlaskClient) -> None:
        resp = client.post(
            "/api/scan-result",
            data="x" * (2 * 1024 * 1024),
            content_type="application/json",
        )
        # Content length > 1MB → 413
        assert resp.status_code == 413

    def test_invalid_finding_format(self, client: FlaskClient) -> None:
        resp = client.post(
            "/api/scan-result",
            json={"tool": "trivy"},  # missing required fields
        )
        assert resp.status_code == 422

    def test_valid_finding_accepted(self, client: FlaskClient, monkeypatch: pytest.MonkeyPatch) -> None:
        # Avoid deduplication and DB saving side effects
        monkeypatch.setattr(
            "devsecops_radar.web.sentry.routes._is_duplicate",
            lambda f: False,
        )
        monkeypatch.setattr(
            "devsecops_radar.web.sentry.routes.save_scan",
            MagicMock(return_value=1),
        )
        resp = client.post(
            "/api/scan-result",
            json={
                "tool": "trivy",
                "id": "CVE-2024-9999",
                "severity": "HIGH",
                "target": "app",
                "title": "Test",
            },
        )
        assert resp.status_code == 200

    def test_buffer_trim(self, client: FlaskClient, monkeypatch: pytest.MonkeyPatch) -> None:
        from devsecops_radar.web.sentry.routes import _LIVE_BUFFER, _LIVE_LOCK

        monkeypatch.setattr(
            "devsecops_radar.web.sentry.routes._is_duplicate",
            lambda f: False,
        )
        monkeypatch.setattr(
            "devsecops_radar.web.sentry.routes.save_scan",
            MagicMock(return_value=1),
        )

        with _LIVE_LOCK:
            _LIVE_BUFFER.clear()

        for i in range(5):
            resp = client.post(
                "/api/scan-result",
                json={
                    "tool": "trivy",
                    "id": f"CVE-{i}",
                    "severity": "LOW",
                    "target": "app",
                    "title": "Test",
                },
            )
            assert resp.status_code == 200

        with _LIVE_LOCK:
            assert len(_LIVE_BUFFER) == 5


class TestGetLiveFindings:
    def test_empty_buffer(self, client: FlaskClient) -> None:
        from devsecops_radar.web.sentry.routes import _LIVE_BUFFER, _LIVE_LOCK
        with _LIVE_LOCK:
            _LIVE_BUFFER.clear()
        resp = client.get("/api/live-findings")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_returns_fresh_findings(self, client: FlaskClient) -> None:
        from devsecops_radar.web.sentry.routes import _LIVE_BUFFER, _LIVE_LOCK
        with _LIVE_LOCK:
            _LIVE_BUFFER.clear()
            now = time.time()
            _LIVE_BUFFER.append((
                {"id": "CVE-1", "tool": "trivy", "severity": "HIGH", "target": "app", "title": "Test"},
                now,
            ))
        resp = client.get("/api/live-findings")
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["id"] == "CVE-1"

    def test_expired_entries_not_returned(self, client: FlaskClient) -> None:
        from devsecops_radar.web.sentry.routes import _LIVE_BUFFER, _LIVE_LOCK, _TTL_SECONDS
        with _LIVE_LOCK:
            _LIVE_BUFFER.clear()
            old = time.time() - _TTL_SECONDS - 10
            _LIVE_BUFFER.append((
                {"id": "EXPIRED", "tool": "trivy", "severity": "LOW", "target": "app", "title": "Old"},
                old,
            ))
        resp = client.get("/api/live-findings")
        assert resp.get_json() == []

    def test_does_not_return_timestamps(self, client: FlaskClient) -> None:
        from devsecops_radar.web.sentry.routes import _LIVE_BUFFER, _LIVE_LOCK
        with _LIVE_LOCK:
            _LIVE_BUFFER.clear()
            now = time.time()
            _LIVE_BUFFER.append((
                {"id": "CVE-2", "tool": "semgrep", "severity": "MEDIUM", "target": "src/app.py", "title": "XSS"},
                now,
            ))
        resp = client.get("/api/live-findings")
        data = resp.get_json()
        assert len(data) == 1
        assert "arrival_time" not in data[0]  # timestamps are stripped
