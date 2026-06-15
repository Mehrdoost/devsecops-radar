import json
import os
from pathlib import Path
from unittest.mock import ANY, MagicMock, mock_open, patch

import pytest
from flask import Flask
from flask.testing import FlaskClient

from devsecops_radar.web.dashboard.routes import (
    _safe_data_path,
    dashboard_bp,
    load_findings,
)


@pytest.fixture
def app_with_dashboard():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.register_blueprint(dashboard_bp)
    return app


@pytest.fixture
def client(app_with_dashboard) -> FlaskClient:
    return app_with_dashboard.test_client()


@pytest.fixture
def auth_headers():
    """Headers that pass authentication – must match conftest.py key."""
    return {"X-API-Key": "test-api-key"}


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------
class TestSafeDataPath:
    def test_valid(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR",
            tmp_path.resolve(),
        )
        f = tmp_path / "data.json"
        f.write_text("{}")
        assert _safe_data_path("data.json") == f.resolve()

    def test_traversal_blocked(self, monkeypatch):
        monkeypatch.setattr(
            "devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR",
            Path("/app"),
        )
        assert _safe_data_path("../etc/passwd") is None

    def test_absolute_outside(self, monkeypatch):
        monkeypatch.setattr(
            "devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR",
            Path("/app"),
        )
        assert _safe_data_path("/etc/passwd") is None


class TestLoadFindings:
    def test_existing(self, tmp_path, monkeypatch):
        data = [{"id": "F1"}]
        f = tmp_path / "findings.json"
        f.write_text(json.dumps(data))
        monkeypatch.setattr(
            "devsecops_radar.web.dashboard.routes.FINDINGS_FILE", "findings.json"
        )
        monkeypatch.setattr(
            "devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR", tmp_path
        )
        assert load_findings() == data

    def test_missing(self, monkeypatch):
        monkeypatch.setattr(
            "devsecops_radar.web.dashboard.routes._safe_data_path", lambda _: None
        )
        assert load_findings() == []

    def test_invalid_json(self, tmp_path, monkeypatch):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        monkeypatch.setattr(
            "devsecops_radar.web.dashboard.routes.FINDINGS_FILE", "bad.json"
        )
        monkeypatch.setattr(
            "devsecops_radar.web.dashboard.routes._ALLOWED_DATA_DIR", tmp_path
        )
        with pytest.raises(json.JSONDecodeError):
            load_findings()


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------
class TestIndex:
    def test_returns_html(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.render_template",
            return_value="<html></html>",
        ):
            resp = client.get("/", headers=auth_headers)
        assert resp.status_code == 200


class TestApiFindings:
    def test_default_pagination(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.get_findings_paginated"
        ) as m:
            m.return_value = []
            resp = client.get("/api/findings", headers=auth_headers)
        assert resp.status_code == 200
        m.assert_called_once_with(1, 50)

    def test_custom_params(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.get_findings_paginated"
        ) as m:
            m.return_value = {}
            client.get("/api/findings?page=2&per_page=10", headers=auth_headers)
        m.assert_called_once_with(2, 10)


class TestApiHistory:
    @patch("devsecops_radar.web.dashboard.routes.db_session")
    def test_default(self, mock_db, client, auth_headers):
        mock_session = MagicMock()
        mock_db.return_value = mock_session
        scan = MagicMock(timestamp=None, risk_score=0, findings=[])
        mock_session.query.return_value.order_by.return_value.all.return_value = [scan]
        resp = client.get("/api/history", headers=auth_headers)
        assert resp.status_code == 200
        assert len(resp.get_json()) == 1

    @patch("devsecops_radar.web.dashboard.routes.db_session")
    def test_week_filter(self, mock_db, client, auth_headers):
        mock_session = MagicMock()
        mock_db.return_value = mock_session
        query = mock_session.query.return_value.order_by.return_value
        query.filter.return_value = query
        scan = MagicMock(timestamp=None, risk_score=0, findings=[])
        query.all.return_value = [scan]
        client.get("/api/history?range=week", headers=auth_headers)
        query.filter.assert_called()

    @patch("devsecops_radar.web.dashboard.routes.db_session")
    def test_invalid_range(self, mock_db, client, auth_headers):
        mock_session = MagicMock()
        mock_db.return_value = mock_session
        query = mock_session.query.return_value.order_by.return_value
        scan = MagicMock(timestamp=None, risk_score=0, findings=[])
        query.all.return_value = [scan]
        client.get("/api/history?range=invalid", headers=auth_headers)
        query.filter.assert_not_called()


class TestScannerStatus:
    @patch("devsecops_radar.web.dashboard.routes.shutil.which")
    def test_all_found(self, mock_which, client, auth_headers):
        mock_which.return_value = "/usr/bin/scanner"
        resp = client.get("/api/scanner-status", headers=auth_headers)
        data = resp.get_json()
        assert all(data.values())
        assert set(data.keys()) == {"trivy", "semgrep", "poutine", "zizmor", "gitleaks"}

    @patch("devsecops_radar.web.dashboard.routes.shutil.which")
    def test_none_found(self, mock_which, client, auth_headers):
        mock_which.return_value = None
        resp = client.get("/api/scanner-status", headers=auth_headers)
        data = resp.get_json()
        assert not any(data.values())


class TestLiveFeed:
    def test_returns_list(self, client, auth_headers):
        with patch("devsecops_radar.web.sentry.routes._LIVE_FINDINGS", ["a", "b"]):
            resp = client.get("/api/live-feed", headers=auth_headers)
        assert resp.get_json() == ["a", "b"]


class TestPolicyStatus:
    def test_no_policy(self, client, auth_headers):
        with patch("pathlib.Path.exists", return_value=False):
            resp = client.get("/api/policy-status", headers=auth_headers)
        assert resp.get_json() == {"status": "no_policy"}

    def test_violated(self, client, auth_headers):
        with patch("pathlib.Path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data='{"max_critical":5}')), \
             patch("devsecops_radar.web.dashboard.routes.load_findings") as mock_load:
            mock_load.return_value = [{"severity": "CRITICAL"}] * 6
            resp = client.get("/api/policy-status", headers=auth_headers)
            data = resp.get_json()
            assert data == {"max_critical": 5, "current_critical": 6, "violated": True}

    def test_not_violated(self, client, auth_headers):
        with patch("pathlib.Path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data='{"max_critical":10}')), \
             patch("devsecops_radar.web.dashboard.routes.load_findings") as mock_load:
            mock_load.return_value = [{"severity": "LOW"}]
            resp = client.get("/api/policy-status", headers=auth_headers)
            assert resp.get_json()["violated"] is False

    def test_invalid_json(self, client, auth_headers):
        with patch("pathlib.Path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="not json")):
            resp = client.get("/api/policy-status", headers=auth_headers)
        assert resp.get_json() == {"status": "error"}


class TestNotifyJira:
    def test_invalid_ids(self, client, auth_headers):
        # send a non-list value to trigger "finding_ids must be a list"
        resp = client.post("/api/notify-jira", json={"finding_ids": "not_a_list"}, headers=auth_headers)
        assert resp.status_code == 400
        assert "finding_ids must be a list" in resp.get_json()["error"]

    def test_no_match(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings",
            return_value=[{"id": "F1"}],
        ):
            resp = client.post(
                "/api/notify-jira",
                json={"finding_ids": ["F2"]},
                headers=auth_headers,
            )
        assert resp.status_code == 400
        assert "No matching findings" in resp.get_json()["error"]

    def test_missing_env(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings",
            return_value=[{"id": "F1"}],
        ):
            with patch.dict(os.environ, {}, clear=True):
                resp = client.post(
                    "/api/notify-jira",
                    json={"finding_ids": ["F1"]},
                    headers=auth_headers,
                )
        assert resp.status_code == 500
        assert "JIRA_URL and JIRA_TOKEN" in resp.get_json()["error"]

    def test_success(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings",
            return_value=[{"id": "F1"}],
        ), \
             patch.dict(os.environ, {"JIRA_URL": "u", "JIRA_TOKEN": "t"}), \
             patch("devsecops_radar.core.notifier.notify_jira") as mock_notify:
            resp = client.post(
                "/api/notify-jira",
                json={"finding_ids": ["F1"]},
                headers=auth_headers,
            )
        assert resp.status_code == 200
        assert resp.get_json() == {"status": "sent"}
        mock_notify.assert_called_once_with([{"id": "F1"}], "u", "t")

    def test_notify_exception(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings",
            return_value=[{"id": "F1"}],
        ), \
             patch.dict(os.environ, {"JIRA_URL": "u", "JIRA_TOKEN": "t"}), \
             patch("devsecops_radar.core.notifier.notify_jira") as mock_notify:
            mock_notify.side_effect = RuntimeError("fail")
            resp = client.post(
                "/api/notify-jira",
                json={"finding_ids": ["F1"]},
                headers=auth_headers,
            )
        assert resp.status_code == 500
        assert "Jira notification failed" in resp.get_json()["error"]


class TestNotifyAsana:
    def test_success(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings",
            return_value=[{"id": "F1"}],
        ), \
             patch.dict(os.environ, {"ASANA_TOKEN": "a", "ASANA_WORKSPACE": "w"}), \
             patch("devsecops_radar.core.notifier.notify_asana") as mock_notify:
            resp = client.post(
                "/api/notify-asana",
                json={"finding_ids": ["F1"]},
                headers=auth_headers,
            )
        assert resp.status_code == 200
        mock_notify.assert_called_once()

    def test_missing_env(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings",
            return_value=[{"id": "F1"}],
        ):
            with patch.dict(os.environ, {}, clear=True):
                resp = client.post(
                    "/api/notify-asana",
                    json={"finding_ids": ["F1"]},
                    headers=auth_headers,
                )
        assert resp.status_code == 500


class TestRag:
    def test_empty(self, client, auth_headers):
        resp = client.get("/api/rag", headers=auth_headers)
        assert resp.get_json() == []

    def test_with_query(self, client, auth_headers):
        with patch("devsecops_radar.web.dashboard.routes.rag_search") as mock_rag:
            mock_rag.return_value = [{"r": "1"}]
            resp = client.get("/api/rag?q=test", headers=auth_headers)
        assert resp.status_code == 200
        mock_rag.assert_called_once_with("test")


class TestSimulate:
    def test_invalid_ids(self, client, auth_headers):
        # send a non-list value to trigger "finding_ids must be a list"
        resp = client.post("/api/simulate", json={"finding_ids": 123}, headers=auth_headers)
        assert resp.status_code == 400
        assert "finding_ids must be a list" in resp.get_json()["error"]

    def test_no_match(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings", return_value=[]
        ):
            resp = client.post(
                "/api/simulate",
                json={"finding_ids": ["F1"]},
                headers=auth_headers,
            )
        assert resp.status_code == 404

    def test_success(self, client, auth_headers):
        findings = [{"id": "F1", "title": "T1"}]
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings",
            return_value=findings,
        ), \
             patch("devsecops_radar.core.attack_simulation.simulate_attack") as sim, \
             patch("devsecops_radar.core.attack_simulation.run_sandboxed_poc") as sandbox, \
             patch("builtins.open", mock_open(read_data="script")):
            sim.return_value = "/tmp/poc.py"
            sandbox.return_value = "sandbox out"
            resp = client.post(
                "/api/simulate",
                json={"finding_ids": ["F1"]},
                headers=auth_headers,
            )
        data = resp.get_json()
        assert data["script"] == "script"
        assert data["sandbox_output"] == "sandbox out"
        assert "T1" in data["description"]

    def test_sandbox_exception(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings",
            return_value=[{"id": "F1"}],
        ), \
             patch("devsecops_radar.core.attack_simulation.simulate_attack") as sim, \
             patch("devsecops_radar.core.attack_simulation.run_sandboxed_poc") as sandbox, \
             patch("builtins.open", mock_open(read_data="script")):
            sim.return_value = "/tmp/poc.py"
            sandbox.side_effect = RuntimeError("fail")
            resp = client.post(
                "/api/simulate",
                json={"finding_ids": ["F1"]},
                headers=auth_headers,
            )
        assert resp.get_json()["sandbox_output"] is None


class TestReport:
    @pytest.fixture
    def findings(self):
        return [
            {
                "tool": "t",
                "id": "F1",
                "severity": "HIGH",
                "target": "app",
                "title": "vuln",
            }
        ]

    @pytest.fixture
    def ai(self):
        return {"executive_summary": "summary text"}

    def test_json(self, client, auth_headers, findings, ai):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings",
            return_value=findings,
        ), \
             patch(
                "devsecops_radar.web.dashboard.routes._safe_data_path",
                return_value=Path("/fake/sum.json"),
            ), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=json.dumps(ai))):
            resp = client.get("/api/report?format=json", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.mimetype == "application/json"
        data = json.loads(resp.data)
        assert data["findings"] == findings
        assert data["ai_summary"] == ai

    def test_html(self, client, auth_headers, findings, ai):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings",
            return_value=findings,
        ), \
             patch(
                "devsecops_radar.web.dashboard.routes._safe_data_path",
                return_value=Path("/fake/sum.json"),
            ), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=json.dumps(ai))):
            resp = client.get("/api/report?format=html", headers=auth_headers)
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "<title>Pipeline Sentinel Report</title>" in html
        assert "summary text" in html

    def test_pdf(self, client, auth_headers, findings, ai):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings",
            return_value=findings,
        ), \
             patch(
                "devsecops_radar.web.dashboard.routes._safe_data_path",
                return_value=Path("/fake/sum.json"),
            ), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=json.dumps(ai))), \
             patch("devsecops_radar.web.dashboard.routes.generate_pdf_report") as pdf, \
             patch("devsecops_radar.web.dashboard.routes.send_file") as send:
            send.return_value = ("pdf", 200)
            client.get("/api/report", headers=auth_headers)
        pdf.assert_called_once_with(findings, ai, ANY, framework=None)
        send.assert_called_once()

    def test_framework(self, client, auth_headers):
        with patch(
            "devsecops_radar.web.dashboard.routes.load_findings", return_value=[]
        ), \
             patch(
                "devsecops_radar.web.dashboard.routes._safe_data_path",
                return_value=None,
            ), \
             patch("devsecops_radar.web.dashboard.routes.generate_pdf_report") as pdf, \
             patch("devsecops_radar.web.dashboard.routes.send_file") as send:
            send.return_value = ("pdf", 200)
            client.get("/api/report?framework=PCI-DSS", headers=auth_headers)
        pdf.assert_called_once_with([], {}, ANY, framework="PCI-DSS")
