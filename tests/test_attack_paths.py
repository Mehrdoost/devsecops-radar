"""Tests for attack_paths routes – final version."""

import json
from io import StringIO

import pytest
from flask import Flask

from devsecops_radar.web.attack_paths.routes import (
    _load_findings,
    attack_paths_bp,
)


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


class TestLoadFindings:
    def test_file_exists(self, monkeypatch):
        data = [{"id": "1", "severity": "HIGH"}]
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.safe_read_open",
            lambda path, base_dir=None: StringIO(json.dumps(data)),
        )
        result = _load_findings()
        assert result == data

    def test_file_missing(self, monkeypatch):
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.safe_read_open",
            lambda path, base_dir=None: (_ for _ in ()).throw(FileNotFoundError),
        )
        assert _load_findings() == []


class TestApiAttackPaths:
    def test_no_findings_returns_empty_graph(self, client, monkeypatch):
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.safe_read_open",
            lambda path, base_dir=None: (_ for _ in ()).throw(FileNotFoundError),
        )
        resp = client.get("/attack-paths")
        assert resp.status_code == 200
        data = resp.json
        assert data["attack_paths"] == []
        assert data["nodes"] == []
        assert data["links"] == []

    def test_no_ai_summary_returns_empty_graph(self, client, monkeypatch):
        findings = [
            {"id": "CVE-1", "severity": "HIGH", "title": "First"},
            {"id": "CVE-2", "severity": "MEDIUM", "title": "Second"},
        ]
        findings_io = StringIO(json.dumps(findings))
        def mock_open(path, base_dir=None):
            if path == "findings.json":
                return findings_io
            raise FileNotFoundError
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.safe_read_open", mock_open
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.FINDINGS_FILE", "findings.json"
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.AI_SUMMARY_FILE", "nonexistent.json"
        )
        resp = client.get("/attack-paths")
        assert resp.status_code == 200
        data = resp.json
        assert data["attack_paths"] == []
        assert data["nodes"] == []
        assert data["links"] == []

    def test_ai_attack_paths_are_used(self, client, monkeypatch):
        findings = [
            {"id": "CVE-1", "severity": "HIGH", "title": "First"},
            {"id": "CVE-2", "severity": "MEDIUM", "title": "Second"},
        ]
        ai_summary = {
            "attack_paths": [
                {
                    "description": "Custom chain",
                    "involved_findings": ["CVE-1"],
                }
            ]
        }
        def mock_open(path, base_dir=None):
            if path == "findings.json":
                return StringIO(json.dumps(findings))
            elif path == "findings_ai_summary.json":
                return StringIO(json.dumps(ai_summary))
            raise FileNotFoundError
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.safe_read_open", mock_open
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.FINDINGS_FILE", "findings.json"
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.AI_SUMMARY_FILE", "findings_ai_summary.json"
        )
        resp = client.get("/attack-paths")
        assert resp.status_code == 200
        data = resp.json
        assert len(data["nodes"]) == 1
        assert data["nodes"][0]["id"] == "CVE-1"
        assert len(data["links"]) == 0  # single node, no link

    def test_ai_summary_without_attack_paths(self, client, monkeypatch):
        findings = [{"id": "CVE-1", "severity": "LOW", "title": "One"}]
        ai_summary = {"executive_summary": "All good"}
        def mock_open(path, base_dir=None):
            if path == "findings.json":
                return StringIO(json.dumps(findings))
            elif path == "findings_ai_summary.json":
                return StringIO(json.dumps(ai_summary))
            raise FileNotFoundError
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.safe_read_open", mock_open
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.FINDINGS_FILE", "findings.json"
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.AI_SUMMARY_FILE", "findings_ai_summary.json"
        )
        resp = client.get("/attack-paths")
        assert resp.status_code == 200
        data = resp.json
        assert data["attack_paths"] == []
        assert data["nodes"] == []
        assert data["links"] == []
