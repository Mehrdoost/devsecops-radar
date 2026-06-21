"""Tests for summary routes (updated – no _safe_data_path, uses safe_read_open)."""

import json
from io import StringIO
from unittest.mock import patch

import pytest
from flask import Flask

from devsecops_radar.web.summary.routes import summary_bp


@pytest.fixture
def app():
    """Create a Flask test app with the summary blueprint."""
    app = Flask(__name__)
    app.register_blueprint(summary_bp)
    return app


@pytest.fixture
def client(app, monkeypatch):
    """Return test client with valid API key header."""
    monkeypatch.setenv("PIPELINE_API_KEY", "test-api-key")
    with app.test_client() as client:
        client.environ_base["HTTP_X_API_KEY"] = "test-api-key"
        yield client


class TestApiSummary:
    def test_file_not_found(self, client, monkeypatch):
        # Mock safe_read_open to raise FileNotFoundError
        monkeypatch.setattr(
            "devsecops_radar.web.summary.routes.safe_read_open",
            lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError),
        )
        resp = client.get("/summary")
        assert resp.status_code == 200
        assert resp.json == {}

    def test_valid_summary_file(self, client, monkeypatch):
        data = {"executive_summary": "All good", "risk_score": 85}
        # Mock safe_read_open to return a file-like object containing the JSON data
        monkeypatch.setattr(
            "devsecops_radar.web.summary.routes.safe_read_open",
            lambda path, base_dir=None: StringIO(json.dumps(data)),
        )
        monkeypatch.setattr(
            "devsecops_radar.web.summary.routes.AI_SUMMARY_FILE",
            "summary.json",
        )
        resp = client.get("/summary")
        assert resp.status_code == 200
        assert resp.json == data

    def test_invalid_json(self, client, monkeypatch):
        # Return a file with invalid JSON content
        monkeypatch.setattr(
            "devsecops_radar.web.summary.routes.safe_read_open",
            lambda path, base_dir=None: StringIO("not json"),
        )
        monkeypatch.setattr(
            "devsecops_radar.web.summary.routes.AI_SUMMARY_FILE",
            "invalid.json",
        )
        resp = client.get("/summary")
        assert resp.status_code == 200
        assert resp.json == {}

    def test_unauthenticated(self, app):
        with app.test_client() as client:
            resp = client.get("/summary")
            assert resp.status_code == 401


class TestSecurityBadge:
    def test_scan_not_found(self, client):
        with patch(
            "devsecops_radar.web.summary.routes.get_scan_by_id",
            return_value=None,
        ):
            resp = client.get("/badge/999.svg")
        assert resp.status_code == 404

    def test_secure_badge(self, client):
        scan_data = {
            "scan_id": 1,
            "findings": [
                {"severity": "LOW"},
                {"severity": "MEDIUM"},
            ],
        }
        with patch(
            "devsecops_radar.web.summary.routes.get_scan_by_id",
            return_value=scan_data,
        ):
            resp = client.get("/badge/1.svg")
        assert resp.status_code == 200
        assert "green" in resp.data.decode()
        assert "Secure" in resp.data.decode()

    def test_warning_badge(self, client):
        scan_data = {
            "scan_id": 2,
            "findings": [
                {"severity": "CRITICAL"},
                {"severity": "CRITICAL"},
                {"severity": "CRITICAL"},
            ],
        }
        with patch(
            "devsecops_radar.web.summary.routes.get_scan_by_id",
            return_value=scan_data,
        ):
            resp = client.get("/badge/2.svg")
        assert resp.status_code == 200
        assert "yellow" in resp.data.decode()
        assert "Warning" in resp.data.decode()

    def test_vulnerable_badge(self, client):
        scan_data = {
            "scan_id": 3,
            "findings": [
                {"severity": "CRITICAL"},
                {"severity": "CRITICAL"},
                {"severity": "CRITICAL"},
                {"severity": "CRITICAL"},
            ],
        }
        with patch(
            "devsecops_radar.web.summary.routes.get_scan_by_id",
            return_value=scan_data,
        ):
            resp = client.get("/badge/3.svg")
        assert resp.status_code == 200
        assert "red" in resp.data.decode()
        assert "Vulnerable" in resp.data.decode()
