"""Tests for the dashboard routes."""

import json
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

# Environment is already set by conftest.py (JWT_SECRET, PIPELINE_API_KEY, DATABASE_URL)
from devsecops_radar.web.dashboard.routes import (
    _safe_data_path,
    dashboard_bp,
    load_findings,
)


@pytest.fixture
def app():
    """Create a Flask test app with the dashboard blueprint."""
    app = Flask(__name__)
    app.register_blueprint(dashboard_bp)
    return app


@pytest.fixture
def client(app):
    """Return a test client with valid API key header."""
    with app.test_client() as client:
        # The conftest sets PIPELINE_API_KEY=test-api-key
        client.environ_base["HTTP_X_API_KEY"] = "test-api-key"
        yield client


# ============================================================================
# _safe_data_path
# ============================================================================
class TestSafeDataPath:
    def test_allowed_file(self, tmp_path):
        base = tmp_path / "allowed"
        base.mkdir()
        f = base / "data.json"
        f.touch()
        with patch(
            "devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR", base
        ):
            assert _safe_data_path("data.json") == f.resolve()

    def test_traversal_blocked(self, tmp_path):
        base = tmp_path / "allowed"
        base.mkdir()
        outside = tmp_path / "evil.txt"
        outside.touch()
        with patch(
            "devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR", base
        ):
            assert _safe_data_path("../evil.txt") is None

    def test_absolute_path_blocked(self, tmp_path):
        base = tmp_path / "allowed"
        base.mkdir()
        with patch(
            "devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR", base
        ):
            assert _safe_data_path(str(tmp_path / "other.txt")) is None


# ============================================================================
# load_findings
# ============================================================================
class TestLoadFindings:
    def test_file_exists(self, tmp_path):
        data = [{"id": "1", "severity": "HIGH"}]
        file = tmp_path / "findings.json"
        file.write_text(json.dumps(data))
        with patch(
            "devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR", tmp_path
        ), patch(
            "devsecops_radar.web.dashboard.routes.FINDINGS_FILE", "findings.json"
        ):
            result = load_findings()
        assert result == data

    def test_file_missing(self, tmp_path):
        with patch(
            "devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR", tmp_path
        ), patch(
            "devsecops_radar.web.dashboard.routes.FINDINGS_FILE",
            "nonexistent.json",
        ):
            assert load_findings() == []

    def test_file_outside_allowed_dir(self, tmp_path):
        outside = tmp_path / "outside.json"
        outside.write_text("[]")
        with patch(
            "devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR",
            tmp_path / "subdir",
        ), patch(
            "devsecops_radar.web.dashboard.routes.FINDINGS_FILE", str(outside)
        ):
            assert load_findings() == []


# ============================================================================
# API endpoints
# ============================================================================
class TestApiFindings:
    @patch("devsecops_radar.web.dashboard.routes.get_findings_paginated")
    def test_returns_paginated_data(self, mock_paginated, client):
        mock_paginated.return_value = {
            "total": 2,
            "page": 1,
            "per_page": 50,
            "data": [{"id": "1"}, {"id": "2"}],
        }
        resp = client.get("/api/findings?page=1&per_page=10")
        assert resp.status_code == 200
        assert resp.json["total"] == 2
        mock_paginated.assert_called_once_with(1, 10)


class TestApiHistory:
    @patch("devsecops_radar.web.dashboard.routes.db_session")
    @patch("devsecops_radar.web.dashboard.routes.Scan")
    def test_returns_history(self, mock_scan, mock_db_session, client):
        mock_session = MagicMock()
        mock_db_session.return_value = mock_session

        scan1 = MagicMock()
        scan1.timestamp = None
        scan1.risk_score = 80
        f1, f2 = MagicMock(), MagicMock()
        f1.severity = "CRITICAL"
        f2.severity = "HIGH"
        scan1.findings = [f1, f2]

        scan2 = MagicMock()
        scan2.timestamp.isoformat.return_value = "2025-01-01T00:00:00"
        scan2.risk_score = 60
        f3 = MagicMock()
        f3.severity = "LOW"
        scan2.findings = [f3]

        mock_session.query.return_value.order_by.return_value.all.return_value = [
            scan1,
            scan2,
        ]
        resp = client.get("/api/history")
        assert resp.status_code == 200
        data = resp.json
        assert len(data) == 2
        assert data[0]["critical"] == 1
        assert data[0]["high"] == 1
        assert data[0]["risk_score"] == 80
        assert data[1]["low"] == 1


class TestApiAttackPaths:
    @patch(
        "devsecops_radar.web.dashboard.routes.load_findings",
        return_value=[
            {"id": "1", "severity": "HIGH", "title": "t1"},
            {"id": "2", "severity": "MEDIUM", "title": "t2"},
        ],
    )
    def test_returns_graph_data(self, mock_load, client):
        resp = client.get("/api/attack-paths")
        assert resp.status_code == 200
        data = resp.json
        assert len(data["nodes"]) == 2
        assert len(data["links"]) == 1

    @patch("devsecops_radar.web.dashboard.routes.load_findings", return_value=[])
    def test_no_findings_returns_empty_graph(self, mock_load, client):
        resp = client.get("/api/attack-paths")
        assert resp.status_code == 200
        assert resp.json == {"nodes": [], "links": []}


class TestApiRag:
    @patch("devsecops_radar.web.dashboard.routes.rag_search")
    def test_returns_rag_results(self, mock_rag, client):
        mock_rag.return_value = [{"id": "1", "tool": "trivy"}]
        resp = client.get("/api/rag?q=test")
        assert resp.status_code == 200
        assert resp.json == [{"id": "1", "tool": "trivy"}]
        mock_rag.assert_called_once_with("test")

    def test_empty_query_returns_empty(self, client):
        resp = client.get("/api/rag?q=")
        assert resp.status_code == 200
        assert resp.json == []


class TestApiSimulate:
    def test_invalid_finding_ids(self, client):
        resp = client.post(
            "/api/simulate",
            json={"finding_ids": "not a list"},
            content_type="application/json",
        )
        assert resp.status_code == 400

    @patch(
        "devsecops_radar.web.dashboard.routes.load_findings", return_value=[]
    )
    def test_findings_not_found(self, mock_load, client):
        resp = client.post(
            "/api/simulate",
            json={"finding_ids": ["F1"]},
            content_type="application/json",
        )
        assert resp.status_code == 404

    @patch(
        "devsecops_radar.web.dashboard.routes.load_findings",
        return_value=[{"id": "F1", "title": "Test", "target": "a.py"}],
    )
    @patch("devsecops_radar.core.attack_simulation.simulate_attack")
    @patch("devsecops_radar.core.attack_simulation.run_sandboxed_poc")
    def test_simulates_selected(
        self, mock_run_sandbox, mock_simulate, mock_load, client, tmp_path
    ):
        script_file = tmp_path / "poc.sh"
        script_file.write_text("#!/bin/bash\necho ok")
        mock_simulate.return_value = str(script_file)
        mock_run_sandbox.return_value = "Sandbox output"

        resp = client.post(
            "/api/simulate",
            json={"finding_ids": ["F1"]},
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.json
        assert "script" in data
        assert data["sandbox_output"] == "Sandbox output"


class TestApiReport:
    @patch(
        "devsecops_radar.web.dashboard.routes.load_findings",
        return_value=[{"id": "1", "severity": "HIGH"}],
    )
    @patch(
        "devsecops_radar.web.dashboard.routes._safe_data_path",
        return_value=None,
    )
    def test_report_json(self, mock_safe, mock_load, client):
        resp = client.get("/api/report?format=json")
        assert resp.status_code == 200
        assert resp.mimetype == "application/json"
        data = json.loads(resp.data)
        assert data["findings"] == [{"id": "1", "severity": "HIGH"}]

    @patch(
        "devsecops_radar.web.dashboard.routes.load_findings",
        return_value=[{"id": "1", "severity": "HIGH", "tool": "trivy",
                        "target": "a.py", "title": "Test"}],
    )
    @patch(
        "devsecops_radar.web.dashboard.routes._safe_data_path",
        return_value=None,
    )
    def test_report_html(self, mock_safe, mock_load, client):
        resp = client.get("/api/report?format=html")
        assert resp.status_code == 200
        assert resp.mimetype == "text/html"
        content = resp.data.decode()
        assert "Pipeline Sentinel Security Report" in content
        assert "trivy" in content

    @patch(
        "devsecops_radar.web.dashboard.routes.load_findings",
        return_value=[{"id": "1"}],
    )
    @patch("devsecops_radar.web.dashboard.routes.generate_pdf_report")
    @patch(
        "devsecops_radar.web.dashboard.routes._safe_data_path",
        return_value=None,
    )
    @patch("devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR")
    @patch("devsecops_radar.web.dashboard.routes.send_file")
    def test_report_pdf(
        self, mock_send, mock_dir, mock_safe, mock_pdf, mock_load, client, tmp_path
    ):
        # Provide a safe temporary path that "exists" for send_file
        mock_dir.__truediv__.return_value = tmp_path / "report.pdf"
        # Ensure the mocked file passes the existence check? No, send_file is mocked entirely.
        mock_send.return_value = ("fake pdf", 200)
        resp = client.get("/api/report?format=pdf")
        assert resp.status_code == 200
        mock_pdf.assert_called_once()


class TestIndex:
    def test_index_page_renders(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Pipeline Sentinel" in resp.data
