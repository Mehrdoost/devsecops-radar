"""Tests for topology routes."""

import json

import pytest
from flask import Flask

from devsecops_radar.web.topology.routes import (
    _safe_data_path,
    topology_bp,
)


@pytest.fixture
def app():
    """Create a Flask test app with the topology blueprint."""
    app = Flask(__name__)
    app.register_blueprint(topology_bp)
    return app


@pytest.fixture
def client(app, monkeypatch):
    """Return test client with a valid API key in the header."""
    monkeypatch.setenv("PIPELINE_API_KEY", "test-api-key")
    with app.test_client() as client:
        client.environ_base["HTTP_X_API_KEY"] = "test-api-key"
        yield client


class TestSafeDataPath:
    def test_traversal_blocked(self, tmp_path, monkeypatch):
        base = tmp_path / "safe"
        base.mkdir()
        outside = tmp_path / "evil.txt"
        outside.touch()
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes._ALLOWED_DATA_DIR", base
        )
        assert _safe_data_path("../evil.txt") is None

    def test_absolute_path_blocked(self, tmp_path, monkeypatch):
        base = tmp_path / "safe"
        base.mkdir()
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes._ALLOWED_DATA_DIR", base
        )
        other = tmp_path / "other.txt"
        assert _safe_data_path(str(other)) is None


class TestApiTopology:
    def test_file_not_present(self, client, monkeypatch):
        # Patch the module constant to a non‑existent file
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.TOPOLOGY_FILE",
            "nonexistent.json",
        )
        resp = client.get("/topology")
        assert resp.status_code == 200
        assert resp.json == {}

    def test_valid_topology_file(self, client, tmp_path, monkeypatch):
        data = {"nodes": [{"id": "srv1"}]}
        file = tmp_path / "topo.json"
        file.write_text(json.dumps(data))

        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes._ALLOWED_DATA_DIR", tmp_path
        )
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.TOPOLOGY_FILE",
            "topo.json",
        )

        resp = client.get("/topology")
        assert resp.status_code == 200
        assert resp.json == data

    def test_file_too_large(self, client, tmp_path, monkeypatch):
        big = {"data": "x" * (11 * 1024 * 1024)}  # > 10 MB
        file = tmp_path / "big.json"
        file.write_text(json.dumps(big))

        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes._ALLOWED_DATA_DIR", tmp_path
        )
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.TOPOLOGY_FILE",
            "big.json",
        )

        resp = client.get("/topology")
        assert resp.status_code == 413
        assert "Topology file too large" in resp.json["error"]
