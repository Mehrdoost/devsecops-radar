"""Tests for SARIF and CycloneDX export functions – updated for lowercase severity & atomic_write."""

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger

from devsecops_radar.core.sarif_export import (
    _safe_int,
    export_cyclonedx,
    export_sarif,
)


# ---------------------------------------------------------------------------
# Capture loguru messages
# ---------------------------------------------------------------------------
@contextmanager
def capture_loguru(level: str = "TRACE"):
    messages: list[str] = []

    def sink(msg):
        messages.append(str(msg))

    handler_id = logger.add(sink, level=level, format="{message}")
    try:
        yield messages
    finally:
        logger.remove(handler_id)


# ---------------------------------------------------------------------------
# Tests for _safe_int
# ---------------------------------------------------------------------------
class TestSafeInt:
    def test_positive_int(self):
        assert _safe_int(42) == 42

    def test_zero_or_negative_returns_default(self):
        assert _safe_int(0) == 1
        assert _safe_int(-5) == 1

    def test_non_int_returns_default(self):
        assert _safe_int("abc") == 1
        assert _safe_int(None) == 1

    def test_string_number(self):
        assert _safe_int("10") == 10


# ---------------------------------------------------------------------------
# Helper to mock atomic_write
# ---------------------------------------------------------------------------
def _mock_atomic_write():
    """Return a context manager that writes to a StringIO and captures the data."""
    f = StringIO()
    mgr = MagicMock()
    mgr.__enter__.return_value = f
    mgr.__exit__.return_value = None
    return mgr, f


# ---------------------------------------------------------------------------
# Tests for export_sarif
# ---------------------------------------------------------------------------
class TestExportSarif:
    @pytest.fixture
    def sample_findings(self):
        return [
            {
                "id": "CVE-2024-001",
                "severity": "CRITICAL",
                "target": "src/main.py",
                "title": "SQL Injection",
                "description": "Found SQL injection",
                "line": 100,
            },
            {
                "id": "CVE-2024-002",
                "severity": "HIGH",
                "target": "tests/test.py",
                "title": "XSS",
            },
            {
                "id": "CVE-2024-001",
                "severity": "MEDIUM",
                "target": "other/file.py",
                "title": "SQL Injection again",
                "line": "5",
            },
        ]

    def test_creates_valid_sarif(self, tmp_path, sample_findings, monkeypatch):
        monkeypatch.chdir(tmp_path)
        output = tmp_path / "report.sarif"
        mgr, f = _mock_atomic_write()
        with patch("devsecops_radar.core.sarif_export.atomic_write", return_value=mgr):
            export_sarif(sample_findings, str(output))
        data = json.loads(f.getvalue())
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 2
        assert len(run["results"]) == 3
        loc = run["results"][0]["locations"][0]
        assert "src/main.py" in loc["physicalLocation"]["artifactLocation"]["uri"]
        assert loc["physicalLocation"]["region"]["startLine"] == 100
        loc2 = run["results"][1]["locations"][0]
        assert loc2["physicalLocation"]["region"]["startLine"] == 1
        loc3 = run["results"][2]["locations"][0]
        assert loc3["physicalLocation"]["region"]["startLine"] == 5

    def test_handles_write_error(self, tmp_path, sample_findings, monkeypatch):
        monkeypatch.chdir(tmp_path)
        output = tmp_path / "report.sarif"
        with patch(
            "devsecops_radar.core.sarif_export.atomic_write",
            side_effect=OSError("permission denied"),
        ):
            with capture_loguru() as msgs:
                export_sarif(sample_findings, str(output))
            assert any("Failed to export SARIF report" in m for m in msgs)

    def test_empty_findings(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        output = tmp_path / "empty.sarif"
        mgr, f = _mock_atomic_write()
        with patch("devsecops_radar.core.sarif_export.atomic_write", return_value=mgr):
            export_sarif([], str(output))
        data = json.loads(f.getvalue())
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []


# ---------------------------------------------------------------------------
# Tests for export_cyclonedx
# ---------------------------------------------------------------------------
class TestExportCycloneDX:
    @pytest.fixture
    def sample_findings(self):
        return [
            {
                "id": "CVE-2024-001",
                "severity": "CRITICAL",
                "target": "app/server.py",
                "description": "RCE",
            },
            {
                "id": "CVE-2024-002",
                "severity": "low",
                "target": "app/server.py",
                "description": "Info leak",
            },
            {
                "id": "CVE-2024-003",
                "severity": "unknown",
                "target": "other/file.py",
            },
        ]

    def test_creates_valid_cyclonedx(self, tmp_path, sample_findings, monkeypatch):
        monkeypatch.chdir(tmp_path)
        output = tmp_path / "report.cdx.json"
        frozen_time = datetime(2025, 6, 11, 12, 0, 0, tzinfo=UTC)
        mgr, f = _mock_atomic_write()
        with patch("devsecops_radar.core.sarif_export.datetime") as mock_dt, \
             patch("devsecops_radar.core.sarif_export.atomic_write", return_value=mgr):
            mock_dt.now.return_value = frozen_time
            export_cyclonedx(sample_findings, str(output))
        data = json.loads(f.getvalue())
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.5"
        assert data["metadata"]["timestamp"] == frozen_time.isoformat()
        components = data["components"]
        assert len(components) == 2
        names = [c["name"] for c in components]
        assert "app/server.py" in names
        assert "other/file.py" in names
        vulns = data["vulnerabilities"]
        assert len(vulns) == 3
        # Severity is now lowercase (critical, low, info)
        assert vulns[0]["ratings"][0]["severity"] == "critical"
        assert vulns[1]["ratings"][0]["severity"] == "low"
        assert vulns[2]["ratings"][0]["severity"] == "info"
        refs = [v["affects"][0]["ref"] for v in vulns]
        assert refs[0] == refs[1]
        assert refs[2] != refs[0]

    def test_handles_write_error(self, tmp_path, sample_findings, monkeypatch):
        monkeypatch.chdir(tmp_path)
        output = tmp_path / "report.cdx.json"
        with patch(
            "devsecops_radar.core.sarif_export.atomic_write",
            side_effect=OSError("disk full"),
        ):
            with capture_loguru() as msgs:
                export_cyclonedx(sample_findings, str(output))
            assert any("Failed to export CycloneDX report" in m for m in msgs)

    def test_empty_findings(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        output = tmp_path / "empty.cdx.json"
        mgr, f = _mock_atomic_write()
        with patch("devsecops_radar.core.sarif_export.atomic_write", return_value=mgr):
            export_cyclonedx([], str(output))
        data = json.loads(f.getvalue())
        assert data["components"] == []
        assert data["vulnerabilities"] == []
