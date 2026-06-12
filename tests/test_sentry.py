"""Tests for sentry routes (live-findings and scan-result)."""


import pytest
from flask import Flask

# We import the blueprint and internal constants
from devsecops_radar.web.sentry.routes import (
    _LIVE_FINDINGS,
    _LIVE_LOCK,
    _MAX_LIVE_FINDINGS,
    sentry_bp,
)


@pytest.fixture(autouse=True)
def clear_live_findings():
    """Ensure the live findings buffer is empty before each test."""
    with _LIVE_LOCK:
        _LIVE_FINDINGS.clear()
    yield
    with _LIVE_LOCK:
        _LIVE_FINDINGS.clear()


@pytest.fixture
def app():
    """Create a Flask test app with the sentry blueprint."""
    app = Flask(__name__)
    app.register_blueprint(sentry_bp)
    # Disable Flask's own MAX_CONTENT_LENGTH so our custom check can be tested
    app.config["MAX_CONTENT_LENGTH"] = None
    return app


@pytest.fixture
def client(app, monkeypatch):
    """Return test client with a valid API key header."""
    monkeypatch.setenv("PIPELINE_API_KEY", "test-api-key")
    with app.test_client() as client:
        client.environ_base["HTTP_X_API_KEY"] = "test-api-key"
        yield client


# ---------------------------------------------------------------------------
# Helper to create a valid finding dict
# ---------------------------------------------------------------------------
def make_finding(**kwargs):
    base = {
        "tool": "semgrep",
        "id": "rule-1",
        "severity": "HIGH",
        "target": "app.py",
        "title": "SQL Injection",
        "description": "Found",
        "line": 10,
    }
    base.update(kwargs)
    return base


# ============================================================================
# Tests for POST /scan-result
# ============================================================================
class TestReceiveScan:
    def test_missing_content_type(self, client):
        resp = client.post("/scan-result", data="{}")
        assert resp.status_code == 400
        assert "Content-Type" in resp.json["error"]

    def test_malformed_json(self, client):
        resp = client.post(
            "/scan-result",
            data="not json",
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "Malformed JSON" in resp.json["error"]

    def test_non_dict_payload(self, client):
        resp = client.post(
            "/scan-result",
            json=[1, 2, 3],
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "Expected a JSON object" in resp.json["error"]

    def test_payload_too_large(self, client, monkeypatch):
        # Reduce the max payload size so that even a minimal valid finding is too large.
        monkeypatch.setattr(
            "devsecops_radar.web.sentry.routes._MAX_PAYLOAD_SIZE", 10
        )
        data = make_finding()
        resp = client.post(
            "/scan-result",
            json=data,
            content_type="application/json",
        )
        assert resp.status_code == 413
        assert "Payload too large" in resp.json["error"]

    def test_invalid_finding_format(self, client):
        # Missing required field 'id'
        data = {"tool": "x", "severity": "LOW", "target": "t", "title": "t"}
        resp = client.post(
            "/scan-result",
            json=data,
            content_type="application/json",
        )
        assert resp.status_code == 422
        assert "Invalid finding format" in resp.json["error"]

    def test_valid_finding_accepted(self, client):
        data = make_finding()
        resp = client.post(
            "/scan-result",
            json=data,
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert resp.json["status"] == "received"
        # The finding should now be in the buffer
        with _LIVE_LOCK:
            assert len(_LIVE_FINDINGS) == 1
            assert _LIVE_FINDINGS[0] == data

    def test_buffer_trim(self, client):
        # Fill the buffer to the maximum limit
        with _LIVE_LOCK:
            for i in range(_MAX_LIVE_FINDINGS):
                _LIVE_FINDINGS.append({"id": str(i)})
        # Now send one more finding
        data = make_finding(id="new")
        resp = client.post("/scan-result", json=data, content_type="application/json")
        assert resp.status_code == 200
        with _LIVE_LOCK:
            # The oldest entry (id=0) should have been removed
            assert _LIVE_FINDINGS[0]["id"] == "1"
            assert _LIVE_FINDINGS[-1]["id"] == "new"
            assert len(_LIVE_FINDINGS) == _MAX_LIVE_FINDINGS


# ============================================================================
# Tests for GET /live-findings
# ============================================================================
class TestGetLiveFindings:
    def test_empty_buffer(self, client):
        resp = client.get("/live-findings")
        assert resp.status_code == 200
        assert resp.json == []

    def test_returns_copy(self, client):
        data = make_finding()
        with _LIVE_LOCK:
            _LIVE_FINDINGS.append(data)
        resp = client.get("/live-findings")
        assert resp.status_code == 200
        assert resp.json == [data]
        # Ensure it's a copy: modifying the response shouldn't affect the internal list
        resp.json.append({"fake": True})
        with _LIVE_LOCK:
            assert len(_LIVE_FINDINGS) == 1
