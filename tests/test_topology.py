import json
import os
from unittest.mock import mock_open, patch

import pytest
from flask import Flask

from devsecops_radar.web.topology.routes import topology_bp


@pytest.fixture
def app():
    app = Flask(__name__)
    app.register_blueprint(topology_bp)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


class TestTopologyAPI:
    def test_file_exists(self, client):
        data = {"nodes": [{"id": 1}]}
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=json.dumps(data))):
            resp = client.get("/topology")
            assert resp.status_code == 200
            assert resp.json == data

    def test_file_not_exists(self, client):
        with patch("os.path.exists", return_value=False):
            resp = client.get("/topology")
            assert resp.status_code == 200
            assert resp.json == {}

    def test_default_filename(self, client):
        with patch.dict(os.environ, {}, clear=True):
            with patch("os.path.exists", return_value=True), \
                 patch("builtins.open", mock_open(read_data='{"default": true}')):
                resp = client.get("/topology")
                assert resp.status_code == 200
                assert resp.json == {"default": True}
