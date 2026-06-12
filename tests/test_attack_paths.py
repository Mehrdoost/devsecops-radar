"""Tests for attack_paths routes."""

import json
from unittest.mock import patch

import pytest
from flask import Flask

from devsecops_radar.web.attack_paths.routes import (
    _safe_data_path,
    _load_findings,
    attack_paths_bp,
)


@pytest.fixture
def app():
    """Create a Flask test app with the attack_paths blueprint."""
    app = Flask(__name__)
    app.register_blueprint(attack_paths_bp)
    return app


@pytest.fixture
def client(app, monkeypatch):
    """Return test client with valid API key header."""
    monkeypatch.setenv("PIPELINE_API_KEY", "test-api-key")
    with app.test_client() as client:
        client.environ_base["HTTP_X_API_KEY"] = "test-api-key"
        yield client


class TestSafeDataPath:
    def test_allowed_file(self, tmp_path):
        base = tmp_path / "allowed"
        base.mkdir()
        f = base / "data.json"
        f.touch()
        with patch(
            "devsecops_radar.web.attack_paths.routes._ALLOWED_DATA_DIR", base
        ):
            assert _safe_data_path("data.json") == f.resolve()

    def test_traversal_blocked(self, tmp_path):
        base = tmp_path / "allowed"
        base.mkdir()
        with patch(
            "devsecops_radar.web.attack_paths.routes._ALLOWED_DATA_DIR", base
        ):
            assert _safe_data_path("../evil.txt") is None


class TestLoadFindings:
    def test_file_exists(self, tmp_path):
        data = [{"id": "1", "severity": "HIGH"}]
        file = tmp_path / "findings.json"
        file.write_text(json.dumps(data))
        with patch(
            "devsecops_radar.web.attack_paths.routes._ALLOWED_DATA_DIR", tmp_path
        ), patch(
            "devsecops_radar.web.attack_paths.routes.FINDINGS_FILE",
            "findings.json",
        ):
            result = _load_findings()
        assert result == data

    def test_file_missing(self, tmp_path):
        with patch(
            "devsecops_radar.web.attack_paths.routes._ALLOWED_DATA_DIR", tmp_path
        ), patch(
            "devsecops_radar.web.attack_paths.routes.FINDINGS_FILE",
            "nonexistent.json",
        ):
            assert _load_findings() == []


class TestApiAttackPaths:
    def test_no_summary_file(self, client, monkeypatch):
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.AI_SUMMARY_FILE",
            "nonexistent.json",
        )
        resp = client.get("/attack-paths")
        assert resp.status_code == 200
        data = resp.json
        assert data["attack_paths"] == []
        assert data["nodes"] == []
        assert data["links"] == []

    def test_empty_attack_paths(self, client, tmp_path, monkeypatch):
        ai_summary = {"attack_paths": []}
        summary_file = tmp_path / "summary.json"
        summary_file.write_text(json.dumps(ai_summary))

        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes._ALLOWED_DATA_DIR",
            tmp_path,
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.AI_SUMMARY_FILE",
            "summary.json",
        )
        resp = client.get("/attack-paths")
        assert resp.status_code == 200
        data = resp.json
        assert data["attack_paths"] == []
        assert data["nodes"] == []
        assert data["links"] == []

    def test_attack_paths_with_findings(self, client, tmp_path, monkeypatch):
        ai_summary = {
            "attack_paths": [
                {
                    "description": "Path from SQLi to RCE",
                    "involved_findings": ["CVE-2024-001", "CVE-2024-002"],
                }
            ]
        }
        findings = [
            {
                "id": "CVE-2024-001",
                "severity": "CRITICAL",
                "title": "SQL Injection",
                "target": "app.py",
            },
            {
                "id": "CVE-2024-002",
                "severity": "HIGH",
                "title": "Remote Code Execution",
                "target": "server.py",
            },
        ]

        summary_file = tmp_path / "summary.json"
        summary_file.write_text(json.dumps(ai_summary))
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))

        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes._ALLOWED_DATA_DIR",
            tmp_path,
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.AI_SUMMARY_FILE",
            "summary.json",
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.FINDINGS_FILE",
            "findings.json",
        )

        resp = client.get("/attack-paths")
        assert resp.status_code == 200
        data = resp.json

        assert len(data["attack_paths"]) == 1
        assert data["attack_paths"][0]["description"] == "Path from SQLi to RCE"

        nodes = data["nodes"]
        assert len(nodes) == 2
        assert nodes[0]["id"] == "CVE-2024-001"
        assert nodes[0]["severity"] == "CRITICAL"
        assert nodes[0]["title"] == "SQL Injection"
        assert nodes[1]["id"] == "CVE-2024-002"
        assert nodes[1]["severity"] == "HIGH"

        links = data["links"]
        assert len(links) == 1
        assert links[0]["source"] == "CVE-2024-001"
        assert links[0]["target"] == "CVE-2024-002"

    def test_finding_not_in_findings_file(self, client, tmp_path, monkeypatch):
        """When involved_findings references an ID not present in findings.json."""
        ai_summary = {
            "attack_paths": [
                {
                    "description": "Unknown finding",
                    "involved_findings": ["UNKNOWN-ID"],
                }
            ]
        }
        findings = [{"id": "OTHER", "severity": "LOW"}]

        summary_file = tmp_path / "summary.json"
        summary_file.write_text(json.dumps(ai_summary))
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))

        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes._ALLOWED_DATA_DIR",
            tmp_path,
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.AI_SUMMARY_FILE",
            "summary.json",
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.FINDINGS_FILE",
            "findings.json",
        )

        resp = client.get("/attack-paths")
        assert resp.status_code == 200
        data = resp.json
        assert len(data["nodes"]) == 1
        assert data["nodes"][0]["severity"] == "UNKNOWN"
        assert data["nodes"][0]["title"] == ""