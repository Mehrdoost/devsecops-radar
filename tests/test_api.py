import pytest
from unittest.mock import patch
from devsecops_radar.web.app import create_app

@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture(autouse=True)
def mock_database():
    # Mock the database function to avoid needing a real DB
    with patch('devsecops_radar.web.dashboard.routes.get_findings_paginated') as mock:
        mock.return_value = {"items": [], "total": 0, "page": 1, "per_page": 50}
        yield

def test_dashboard_page(client):
    resp = client.get('/')
    assert resp.status_code == 200

def test_findings_api_requires_key_when_set(monkeypatch, client):
    monkeypatch.setenv("PIPELINE_API_KEY", "secret")
    resp = client.get('/api/findings')
    assert resp.status_code == 401
    resp = client.get('/api/findings', headers={"X-API-Key": "secret"})
    assert resp.status_code == 200

def test_findings_api_open_when_disabled(monkeypatch, client):
    monkeypatch.setenv("PIPELINE_API_KEY", "disabled")
    resp = client.get('/api/findings')
    assert resp.status_code == 200