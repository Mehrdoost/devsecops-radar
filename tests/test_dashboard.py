import json
from unittest.mock import mock_open, patch

import pytest
from flask import Flask

from devsecops_radar.web.dashboard.routes import dashboard_bp, load_findings


# ------------------------------------------------------------
# load_findings
# ------------------------------------------------------------
class TestLoadFindings:
    def test_file_missing(self):
        with patch("os.path.exists", return_value=False):
            assert load_findings() == []

    def test_file_exists(self):
        data = [{"id": "R1", "tool": "Semgrep"}]
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=json.dumps(data))):
            result = load_findings()
            assert result == data


# ------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------
@pytest.fixture
def app(monkeypatch):
    """Create app with API key set to 'testkey' and monkeypatch settings."""
    monkeypatch.setenv("PIPELINE_API_KEY", "testkey")
    # Force settings to reload the key (since settings is a singleton already imported)
    from devsecops_radar.core.settings import settings
    settings.PIPELINE_API_KEY = "testkey"

    app = Flask(__name__)
    app.config["TESTING"] = True
    app.register_blueprint(dashboard_bp)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


# Helper to add auth header
def auth_headers():
    return {"X-API-Key": "testkey"}


# ------------------------------------------------------------
# GET /
# ------------------------------------------------------------
class TestIndex:
    def test_returns_200(self, client):
        with patch("devsecops_radar.web.dashboard.routes.load_findings",
                   return_value=[]):
            resp = client.get("/")
            assert resp.status_code == 200
            assert b"Pipeline Sentinel" in resp.data


# ------------------------------------------------------------
# GET /api/findings
# ------------------------------------------------------------
class TestApiFindings:
    def test_returns_paginated_data(self, client):
        mock_data = {"data": [], "total": 0, "page": 1, "per_page": 50}
        with patch("devsecops_radar.web.dashboard.routes.get_findings_paginated",
                   return_value=mock_data) as mock_fn:
            resp = client.get("/api/findings?page=2&per_page=10",
                              headers=auth_headers())
            assert resp.status_code == 200
            mock_fn.assert_called_once_with(2, 10)
            assert resp.json == mock_data

    def test_default_params(self, client):
        mock_data = {"data": [], "total": 0, "page": 1, "per_page": 50}
        with patch("devsecops_radar.web.dashboard.routes.get_findings_paginated",
                   return_value=mock_data) as mock_fn:
            client.get("/api/findings", headers=auth_headers())
            mock_fn.assert_called_once_with(1, 50)


# ------------------------------------------------------------
# GET /api/history
# ------------------------------------------------------------
class TestApiHistory:
    def test_returns_history(self, client):
        mock_history = [{"scan_id": 1, "risk_score": 80}]
        with patch("devsecops_radar.web.dashboard.routes.get_all_scans",
                   return_value=mock_history):
            resp = client.get("/api/history", headers=auth_headers())
            assert resp.status_code == 200
            assert resp.json == mock_history


# ------------------------------------------------------------
# GET /api/rag
# ------------------------------------------------------------
class TestApiRag:
    def test_empty_query_returns_empty_list(self, client):
        resp = client.get("/api/rag", headers=auth_headers())
        assert resp.status_code == 200
        assert resp.json == []

    def test_query_returns_results(self, client):
        mock_results = [{"tool": "Semgrep", "id": "R1"}]
        with patch("devsecops_radar.web.dashboard.routes.rag_search",
                   return_value=mock_results) as mock_rag:
            resp = client.get("/api/rag?q=SQLi", headers=auth_headers())
            assert resp.status_code == 200
            mock_rag.assert_called_once_with("SQLi")
            assert resp.json == mock_results


# ------------------------------------------------------------
# POST /api/simulate
# ------------------------------------------------------------
class TestApiSimulate:
    def test_no_finding_ids(self, client):
        resp = client.post("/api/simulate", json={}, headers=auth_headers())
        assert resp.status_code == 400
        assert resp.json["error"] == "No finding IDs"

    def test_findings_not_found(self, client):
        with patch("devsecops_radar.web.dashboard.routes.load_findings",
                   return_value=[{"id": "R1"}]):
            resp = client.post("/api/simulate", json={"finding_ids": ["R2"]},
                               headers=auth_headers())
            assert resp.status_code == 404
            assert resp.json["error"] == "Not found"

    def test_simulation_success(self, client):
        findings = [{"id": "R1", "title": "XSS", "tool": "Semgrep"}]
        mock_script = "#!/bin/bash\necho 'poc'"
        with patch("devsecops_radar.web.dashboard.routes.load_findings",
                   return_value=findings), \
             patch("devsecops_radar.core.attack_simulation.simulate_attack",
                   return_value="/tmp/poc.sh"), \
             patch("devsecops_radar.core.attack_simulation.run_sandboxed_poc",
                   return_value="sandbox output"), \
             patch("builtins.open", mock_open(read_data=mock_script)):
            resp = client.post("/api/simulate", json={"finding_ids": ["R1"]},
                               headers=auth_headers())
            assert resp.status_code == 200
            data = resp.json
            assert mock_script in data["script"]
            assert "R1: XSS" in data["description"]
            assert data["sandbox_output"] == "sandbox output"

    def test_sandbox_poc_exception(self, client):
        findings = [{"id": "R1", "title": "XSS"}]
        with patch("devsecops_radar.web.dashboard.routes.load_findings",
                   return_value=findings), \
             patch("devsecops_radar.core.attack_simulation.simulate_attack",
                   return_value="/tmp/poc.sh"), \
             patch("devsecops_radar.core.attack_simulation.run_sandboxed_poc",
                   side_effect=Exception("docker missing")), \
             patch("builtins.open", mock_open(read_data="script")):
            resp = client.post("/api/simulate", json={"finding_ids": ["R1"]},
                               headers=auth_headers())
            assert resp.status_code == 200
            assert resp.json["sandbox_output"] is None


# ------------------------------------------------------------
# GET /api/report
# ------------------------------------------------------------
class TestApiReport:
    def test_json_report(self, client):
        findings = [{"id": "R1", "tool": "Semgrep"}]
        with patch("devsecops_radar.web.dashboard.routes.load_findings",
                   return_value=findings), \
             patch("os.path.exists", return_value=False):
            resp = client.get("/api/report?format=json", headers=auth_headers())
            assert resp.status_code == 200
            assert resp.content_type == "application/json"
            data = json.loads(resp.data)
            assert data["findings"] == findings

    def test_html_report(self, client):
        with patch("devsecops_radar.web.dashboard.routes.load_findings",
                   return_value=[]), \
             patch("os.path.exists", return_value=False):
            resp = client.get("/api/report?format=html", headers=auth_headers())
            assert resp.status_code == 200
            assert b"<html>" in resp.data

    def test_pdf_report(self, client):
        with patch("devsecops_radar.web.dashboard.routes.load_findings",
                   return_value=[]), \
             patch("devsecops_radar.web.dashboard.routes.generate_pdf_report") as mock_pdf, \
             patch("os.path.exists", return_value=False), \
             patch("devsecops_radar.web.dashboard.routes.send_file") as mock_send:
            mock_send.return_value = ("pdf data", 200)
            resp = client.get("/api/report", headers=auth_headers())
            assert resp.status_code == 200
            mock_pdf.assert_called_once()

    def test_report_default_format(self, client):
        with patch("devsecops_radar.web.dashboard.routes.load_findings",
                   return_value=[]), \
             patch("devsecops_radar.web.dashboard.routes.generate_pdf_report"), \
             patch("os.path.exists", return_value=False), \
             patch("devsecops_radar.web.dashboard.routes.send_file",
                   return_value=("pdf data", 200)):
            resp = client.get("/api/report", headers=auth_headers())
            assert resp.status_code == 200
