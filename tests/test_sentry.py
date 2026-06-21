"""Tests for sentry routes (updated – _LIVE_BUFFER deque with TTL, get_live_snapshot)."""

import time

import pytest
from flask import Flask

from devsecops_radar.web.sentry.routes import (
    _LIVE_BUFFER,
    _LIVE_LOCK,
    _MAX_LIVE_FINDINGS,
    _TTL_SECONDS,
    get_live_snapshot,
    sentry_bp,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _insert_finding(data: dict, timestamp: float | None = None):
    """Insert a finding into the live buffer (thread‑safe)."""
    ts = timestamp if timestamp is not None else time.time()
    with _LIVE_LOCK:
        _LIVE_BUFFER.append((data, ts))


def _clear_buffer():
    with _LIVE_LOCK:
        _LIVE_BUFFER.clear()


@pytest.fixture(autouse=True)
def clear_live_buffer():
    """Ensure the live buffer is empty before each test."""
    _clear_buffer()
    yield
    _clear_buffer()


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
        # Should be retrievable via snapshot
        snapshot = get_live_snapshot()
        assert len(snapshot) == 1
        assert snapshot[0] == data

    def test_buffer_trim(self, client):
        # Fill the buffer to the maximum limit
        now = time.time()
        with _LIVE_LOCK:
            for i in range(_MAX_LIVE_FINDINGS):
                _LIVE_BUFFER.append(({"id": str(i)}, now))
        # Send one more finding via the endpoint
        data = make_finding(id="new")
        resp = client.post("/scan-result", json=data, content_type="application/json")
        assert resp.status_code == 200
        # Check that the oldest was evicted
        snapshot = get_live_snapshot()
        assert len(snapshot) == _MAX_LIVE_FINDINGS
        ids = [f["id"] for f in snapshot]
        assert "0" not in ids  # oldest removed
        assert "new" in ids
        # The oldest remaining should be "1"
        assert ids[0] == "1"


# ============================================================================
# Tests for GET /live-findings (now uses get_live_snapshot)
# ============================================================================
class TestGetLiveFindings:
    def test_empty_buffer(self, client):
        resp = client.get("/live-findings")
        assert resp.status_code == 200
        assert resp.json == []

    def test_returns_fresh_findings(self, client):
        data = make_finding()
        _insert_finding(data)
        resp = client.get("/live-findings")
        assert resp.status_code == 200
        assert resp.json == [data]

    def test_expired_entries_not_returned(self, client, monkeypatch):
        # Insert an old finding that should be pruned
        old_time = time.time() - (_TTL_SECONDS + 10)
        _insert_finding(make_finding(id="old"), timestamp=old_time)
        # Insert a fresh one
        fresh_data = make_finding(id="fresh")
        _insert_finding(fresh_data)
        resp = client.get("/live-findings")
        assert resp.status_code == 200
        assert resp.json == [fresh_data]  # old one pruned

    def test_does_not_return_timestamps(self, client):
        data = make_finding()
        _insert_finding(data)
        resp = client.get("/live-findings")
        assert resp.status_code == 200
        # Each item should be the original dict, not a tuple
        assert resp.json[0] == data
