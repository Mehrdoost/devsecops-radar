"""Tests for topology routes (updated – mock safe_read_open & set cwd)."""

import json
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from devsecops_radar.web.topology.routes import topology_bp


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


class TestApiTopology:
    def test_file_not_present(self, client, monkeypatch):
        """When safe_read_open raises FileNotFoundError, route returns empty dict."""
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.safe_read_open",
            lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError),
        )
        resp = client.get("/topology")
        assert resp.status_code == 200
        assert resp.json == {}

    def test_valid_topology_file(self, client, monkeypatch, tmp_path):
        """Valid file content is returned as JSON."""
        # Change cwd so that safe_read_open allows the file
        monkeypatch.chdir(tmp_path)
        data = {"nodes": [{"id": "srv1"}]}
        file = tmp_path / "topo.json"
        file.write_text(json.dumps(data))

        # Mock safe_read_open to return a file-like object that supports fileno()
        mock_file = MagicMock()
        mock_file.__enter__.return_value = mock_file
        mock_file.__exit__.return_value = None
        mock_file.fileno.return_value = 1          # dummy fd
        mock_file.read.return_value = json.dumps(data)
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.safe_read_open",
            lambda path, base_dir=None: mock_file,
        )
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.TOPOLOGY_FILE",
            "topo.json",
        )
        # Also mock os.fstat so that size check passes
        with patch("os.fstat") as mock_fstat:
            mock_fstat.return_value.st_size = 100  # small size
            resp = client.get("/topology")
        assert resp.status_code == 200
        assert resp.json == data

    def test_file_too_large(self, client, monkeypatch, tmp_path):
        """When file size exceeds 10 MB, returns 413 error."""
        monkeypatch.chdir(tmp_path)
        big_data = {"data": "x" * (11 * 1024 * 1024)}  # > 10 MB
        file = tmp_path / "big.json"
        file.write_text(json.dumps(big_data))

        mock_file = MagicMock()
        mock_file.__enter__.return_value = mock_file
        mock_file.__exit__.return_value = None
        mock_file.fileno.return_value = 1
        mock_file.read.return_value = json.dumps(big_data)
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.safe_read_open",
            lambda path, base_dir=None: mock_file,
        )
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.TOPOLOGY_FILE",
            "big.json",
        )
        with patch("os.fstat") as mock_fstat:
            mock_fstat.return_value.st_size = 11 * 1024 * 1024 + 1
            resp = client.get("/topology")
        assert resp.status_code == 413
        assert "Topology file too large" in resp.json["error"]

    def test_invalid_json(self, client, monkeypatch, tmp_path):
        """Invalid JSON returns empty dict."""
        monkeypatch.chdir(tmp_path)
        mock_file = MagicMock()
        mock_file.__enter__.return_value = mock_file
        mock_file.__exit__.return_value = None
        mock_file.fileno.return_value = 1
        mock_file.read.return_value = "not json"
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.safe_read_open",
            lambda path, base_dir=None: mock_file,
        )
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.TOPOLOGY_FILE",
            "any.json",
        )
        with patch("os.fstat") as mock_fstat:
            mock_fstat.return_value.st_size = 100
            resp = client.get("/topology")
        # Route catches JSONDecodeError and returns empty dict with status 200
        assert resp.status_code == 200
        assert resp.json == {}

    def test_unauthenticated(self, app):
        with app.test_client() as client:
            resp = client.get("/topology")
            assert resp.status_code == 401
