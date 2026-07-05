"""Tests for attack_paths routes – updated to match database‑driven implementation."""

import json
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from devsecops_radar.web.attack_paths.routes import attack_paths_bp


@pytest.fixture
def app():
    app = Flask(__name__)
    app.register_blueprint(attack_paths_bp)
    return app


@pytest.fixture
def client(app, monkeypatch):
    monkeypatch.setenv("PIPELINE_API_KEY", "test-api-key")
    with app.test_client() as client:
        client.environ_base["HTTP_X_API_KEY"] = "test-api-key"
        yield client


class TestApiAttackPaths:
    def test_no_findings_returns_empty_graph(self, client):
        """When the database has no AI analysis and no findings, return empty graph."""
        with patch(
            "devsecops_radar.web.attack_paths.routes.SessionLocal"
        ) as mock_session_local:
            mock_session = MagicMock()
            mock_session_local.return_value = mock_session

            # First call: get latest AI analysis (returns None)
            mock_scan_query = mock_session.query.return_value.order_by.return_value
            mock_scan_query.first.return_value = None

            resp = client.get("/attack-paths")
            assert resp.status_code == 200
            data = resp.json
            assert data["attack_paths"] == []
            assert data["nodes"] == []
            assert data["links"] == []

    def test_no_ai_summary_returns_empty_graph(self, client):
        """When no AI analysis exists, fallback graph is built from findings."""
        with patch(
            "devsecops_radar.web.attack_paths.routes.SessionLocal"
        ) as mock_session_local:
            mock_session = MagicMock()
            mock_session_local.return_value = mock_session

            # First call: get latest AI analysis (returns None)
            mock_scan_query = mock_session.query.return_value.order_by.return_value
            mock_scan_query.first.return_value = None

            # Second call: get findings for fallback graph
            mock_finding_query = mock_session.query.return_value
            mock_finding_query.limit.return_value.all.return_value = [
                MagicMock(rule_id="CVE-1", tool="trivy", severity="HIGH", target="/app", title="First"),
                MagicMock(rule_id="CVE-2", tool="trivy", severity="MEDIUM", target="/app", title="Second"),
            ]

            resp = client.get("/attack-paths")
            assert resp.status_code == 200
            data = resp.json
            # With two findings on the same target, one edge should be created
            assert len(data["nodes"]) == 2
            assert len(data["links"]) == 1  # one edge connecting the two nodes

    def test_ai_attack_paths_are_used(self, client):
        """When AI analysis exists, its attack paths are used."""
        ai_summary_data = {
            "attack_paths": [
                {
                    "description": "Custom chain",
                    "involved_findings": ["CVE-1"],
                }
            ]
        }

        with patch(
            "devsecops_radar.web.attack_paths.routes.SessionLocal"
        ) as mock_session_local:
            mock_session = MagicMock()
            mock_session_local.return_value = mock_session

            # First call: get latest AI analysis
            mock_scan = MagicMock()
            mock_scan.ai_summary_json = json.dumps(ai_summary_data)
            mock_scan_query = mock_session.query.return_value.order_by.return_value
            mock_scan_query.first.return_value = mock_scan

            # Second call: get findings matching involved IDs
            mock_finding = MagicMock()
            mock_finding.rule_id = "CVE-1"
            mock_finding.severity = "HIGH"
            mock_finding.title = "First"
            mock_session.query.return_value.filter.return_value.limit.return_value.all.return_value = [
                mock_finding
            ]

            resp = client.get("/attack-paths")
            assert resp.status_code == 200
            data = resp.json
            assert len(data["nodes"]) == 1
            assert data["nodes"][0]["id"] == "CVE-1"
            assert len(data["links"]) == 0  # single node, no link

    def test_ai_summary_without_attack_paths(self, client):
        """When AI summary has no attack_paths, returns empty graph."""
        ai_summary_data = {"executive_summary": "All good"}

        with patch(
            "devsecops_radar.web.attack_paths.routes.SessionLocal"
        ) as mock_session_local:
            mock_session = MagicMock()
            mock_session_local.return_value = mock_session

            # First call: get latest AI analysis
            mock_scan = MagicMock()
            mock_scan.ai_summary_json = json.dumps(ai_summary_data)
            mock_scan_query = mock_session.query.return_value.order_by.return_value
            mock_scan_query.first.return_value = mock_scan

            resp = client.get("/attack-paths")
            assert resp.status_code == 200
            data = resp.json
            assert data["attack_paths"] == []
            assert data["nodes"] == []
            assert data["links"] == []
