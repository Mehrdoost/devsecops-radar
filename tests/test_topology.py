"""Tests for infrastructure topology API endpoint."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask
from flask.testing import FlaskClient

from devsecops_radar.core.database import init_db
from devsecops_radar.web.app import create_app


@pytest.fixture
def app() -> Flask:
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


@pytest.fixture(autouse=True)
def _init_db() -> None:
    init_db()


@pytest.fixture(autouse=True)
def _reset_topology_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the topology module to use *tmp_path* as its working directory."""
    import devsecops_radar.web.topology.routes as topo_routes
    topo_routes._cache = None
    topo_routes._cache_time = 0.0
    monkeypatch.setattr(topo_routes, "_ALLOWED_DATA_DIR", tmp_path.resolve())


class TestApiTopology:
    def test_valid_topology_returns_json(
        self, client: FlaskClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "topology.json").write_text(
            json.dumps({"assets": [{"name": "srv1"}]}), encoding="utf-8"
        )
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.TOPOLOGY_FILE", "topology.json"
        )
        resp = client.get("/api/topology")
        assert resp.status_code == 200
        assert "assets" in resp.get_json()

    def test_file_too_large_returns_413(
        self, client: FlaskClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "big.json").write_text("{}")
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.TOPOLOGY_FILE", "big.json"
        )
        with patch("os.fstat") as mock_fstat:
            mock_fstat.return_value.st_size = 11 * 1024 * 1024  # 11 MB
            resp = client.get("/api/topology")
        assert resp.status_code == 413

    def test_invalid_json_returns_empty_object(
        self, client: FlaskClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "bad.json").write_text("not json", encoding="utf-8")
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.TOPOLOGY_FILE", "bad.json"
        )
        resp = client.get("/api/topology")
        assert resp.status_code == 200
        assert resp.get_json() == {}

    def test_path_outside_base_is_rejected(
        self, client: FlaskClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.TOPOLOGY_FILE", "../secret.json"
        )
        resp = client.get("/api/topology")
        assert resp.status_code == 403

    def test_cache_is_used_on_second_call(
        self, client: FlaskClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        topo = {"nodes": [{"id": "node1"}]}
        (tmp_path / "topology.json").write_text(json.dumps(topo), encoding="utf-8")
        monkeypatch.setattr(
            "devsecops_radar.web.topology.routes.TOPOLOGY_FILE", "topology.json"
        )
        resp1 = client.get("/api/topology")
        assert resp1.status_code == 200
        (tmp_path / "topology.json").write_text("{}")
        resp2 = client.get("/api/topology")
        assert "nodes" in resp2.get_json()

    def test_cache_expires_after_ttl(
        self, client: FlaskClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import devsecops_radar.web.topology.routes as topo_routes

        topo = {"nodes": [{"id": "n1"}]}
        (tmp_path / "topology.json").write_text(json.dumps(topo), encoding="utf-8")
        monkeypatch.setattr(topo_routes, "TOPOLOGY_FILE", "topology.json")

        client.get("/api/topology")
        topo_routes._cache_time = time.time() - 60

        (tmp_path / "topology.json").write_text(
            json.dumps({"nodes": [{"id": "n2"}]}), encoding="utf-8"
        )
        resp = client.get("/api/topology")
        assert resp.get_json()["nodes"][0]["id"] == "n2"
