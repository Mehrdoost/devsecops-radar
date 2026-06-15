"""Tests for attack_paths routes – updated for fallback chain."""

import json
from pathlib import Path
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
    def test_no_findings_returns_empty_graph(self, client, tmp_path, monkeypatch):
        """When there are no findings, the graph should be completely empty."""
        # No findings file present
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes._ALLOWED_DATA_DIR", tmp_path
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.FINDINGS_FILE",
            "nonexistent.json",
        )
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

    def test_fallback_chain_when_no_ai_summary(self, client, tmp_path, monkeypatch):
        """When no AI summary exists, all findings become a linear chain."""
        findings = [
            {"id": "CVE-1", "severity": "HIGH", "title": "First"},
            {"id": "CVE-2", "severity": "MEDIUM", "title": "Second"},
        ]
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))

        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes._ALLOWED_DATA_DIR", tmp_path
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.FINDINGS_FILE",
            "findings.json",
        )
        # No AI summary file
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.AI_SUMMARY_FILE",
            "nonexistent.json",
        )
        resp = client.get("/attack-paths")
        assert resp.status_code == 200
        data = resp.json
        assert len(data["nodes"]) == 2
        assert data["nodes"][0]["id"] == "CVE-1"
        assert data["nodes"][0]["severity"] == "HIGH"
        assert data["nodes"][1]["id"] == "CVE-2"
        assert len(data["links"]) == 1
        assert data["links"][0]["source"] == "CVE-1"
        assert data["links"][0]["target"] == "CVE-2"

    def test_ai_attack_paths_take_priority(self, client, tmp_path, monkeypatch):
        """When AI summary provides involved_findings, those are used."""
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
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))
        summary_file = tmp_path / "summary.json"
        summary_file.write_text(json.dumps(ai_summary))

        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes._ALLOWED_DATA_DIR", tmp_path
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.FINDINGS_FILE",
            "findings.json",
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.AI_SUMMARY_FILE",
            "summary.json",
        )
        resp = client.get("/attack-paths")
        assert resp.status_code == 200
        data = resp.json
        # Only one node from the AI path
        assert len(data["nodes"]) == 1
        assert data["nodes"][0]["id"] == "CVE-1"
        assert len(data["links"]) == 0  # single node has no link

    def test_ai_summary_exists_but_no_attack_paths(self, client, tmp_path, monkeypatch):
        """When AI summary exists but has no attack_paths, fallback to linear chain."""
        findings = [
            {"id": "CVE-1", "severity": "LOW", "title": "One"},
        ]
        ai_summary = {"executive_summary": "All good"}  # no attack_paths

        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))
        summary_file = tmp_path / "summary.json"
        summary_file.write_text(json.dumps(ai_summary))

        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes._ALLOWED_DATA_DIR", tmp_path
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.FINDINGS_FILE",
            "findings.json",
        )
        monkeypatch.setattr(
            "devsecops_radar.web.attack_paths.routes.AI_SUMMARY_FILE",
            "summary.json",
        )
        resp = client.get("/attack-paths")
        assert resp.status_code == 200
        data = resp.json
        assert len(data["nodes"]) == 1
        assert data["nodes"][0]["id"] == "CVE-1"