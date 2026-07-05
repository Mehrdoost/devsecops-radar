"""Tests for the summary page endpoint."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

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


class TestApiSummary:
    def test_file_not_found(self, client: FlaskClient) -> None:
        with patch("devsecops_radar.web.summary.routes.SessionLocal") as mock_session_local:
            mock_session = MagicMock()
            mock_session_local.return_value = mock_session
            mock_session.query.return_value.filter.return_value.order_by.return_value.first.return_value = None
            resp = client.get("/api/summary")
            assert resp.status_code == 200
            assert resp.get_json() == {}

    def test_valid_summary_file(self, client: FlaskClient) -> None:
        data = {"executive_summary": "All good", "risk_score": 85}
        with patch("devsecops_radar.web.summary.routes.SessionLocal") as mock_session_local:
            mock_session = MagicMock()
            mock_session_local.return_value = mock_session

            mock_scan = MagicMock()
            mock_scan.id = 1
            mock_scan.ai_summary_json = json.dumps(data)
            mock_session.query.return_value.filter.return_value.order_by.return_value.first.return_value = mock_scan
            mock_session.query.return_value.filter.return_value.count.side_effect = [10, 2]

            resp = client.get("/api/summary")
            assert resp.status_code == 200
            result = resp.get_json()
            assert result["executive_summary"] == data["executive_summary"]
            assert result["risk_score"] == 85

    def test_invalid_json(self, client: FlaskClient) -> None:
        with patch("devsecops_radar.web.summary.routes.SessionLocal") as mock_session_local:
            mock_session = MagicMock()
            mock_session_local.return_value = mock_session

            mock_scan = MagicMock()
            mock_scan.id = 1
            mock_scan.ai_summary_json = "not json"
            mock_session.query.return_value.filter.return_value.order_by.return_value.first.return_value = mock_scan

            resp = client.get("/api/summary")
            assert resp.status_code == 200
            assert resp.get_json() == {}
