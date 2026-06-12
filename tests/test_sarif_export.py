"""Tests for SARIF and CycloneDX export functions."""

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from loguru import logger

from devsecops_radar.core.sarif_export import (
    _get_safe_path,
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
# Tests for _get_safe_path
# ---------------------------------------------------------------------------
class TestGetSafePath:
    def test_safe_path_inside_allowed(self, tmp_path):
        p = _get_safe_path("report.json", str(tmp_path))
        assert p.resolve() == (tmp_path / "report.json").resolve()

    def test_path_traversal_blocked(self, tmp_path):
        with pytest.raises(ValueError, match="Path traversal attempt"):
            _get_safe_path("../../etc/passwd", str(tmp_path))

    def test_absolute_path_blocked(self, tmp_path):
        # Even if absolute, it won't be relative to the base, so ValueError
        with pytest.raises(ValueError):
            _get_safe_path("/etc/passwd", str(tmp_path))

    def test_default_allowed_dir(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        safe = _get_safe_path("test.json")
        assert safe == (Path.cwd() / "test.json").resolve()


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
                # missing description and line
            },
            {
                # second occurrence of same rule id
                "id": "CVE-2024-001",
                "severity": "MEDIUM",
                "target": "other/file.py",
                "title": "SQL Injection again",
                "line": "5",
            },
        ]

    def test_creates_valid_sarif(self, tmp_path, sample_findings):
        output = tmp_path / "report.sarif"
        # Bypass path traversal check; we trust tmp_path
        with patch(
            "devsecops_radar.core.sarif_export._get_safe_path",
            return_value=output.resolve(),
        ):
            export_sarif(sample_findings, str(output))
        assert output.exists()
        with open(output, encoding="utf-8") as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        # 2 unique rules
        assert len(run["tool"]["driver"]["rules"]) == 2
        # 3 results
        assert len(run["results"]) == 3
        # Check URI encoding and line number
        loc = run["results"][0]["locations"][0]
        assert "src/main.py" in loc["physicalLocation"]["artifactLocation"]["uri"]
        assert loc["physicalLocation"]["region"]["startLine"] == 100
        # second result missing line -> default 1
        loc2 = run["results"][1]["locations"][0]
        assert loc2["physicalLocation"]["region"]["startLine"] == 1
        # third result has line "5" -> int 5
        loc3 = run["results"][2]["locations"][0]
        assert loc3["physicalLocation"]["region"]["startLine"] == 5

    def test_handles_write_error(self, tmp_path, sample_findings):
        output = tmp_path / "report.sarif"
        with patch("builtins.open", side_effect=OSError("permission denied")):
            with capture_loguru() as msgs:
                export_sarif(sample_findings, str(output))
            assert any("Failed to export SARIF report" in m for m in msgs)

    def test_empty_findings(self, tmp_path):
        output = tmp_path / "empty.sarif"
        with patch(
            "devsecops_radar.core.sarif_export._get_safe_path",
            return_value=output.resolve(),
        ):
            export_sarif([], str(output))
        with open(output, encoding="utf-8") as f:
            data = json.load(f)
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
                "severity": "low",  # lower case to test mapping
                "target": "app/server.py",  # same component
                "description": "Info leak",
            },
            {
                "id": "CVE-2024-003",
                "severity": "unknown",
                "target": "other/file.py",
            },
        ]

    def test_creates_valid_cyclonedx(self, tmp_path, sample_findings):
        output = tmp_path / "report.cdx.json"
        frozen_time = datetime(2025, 6, 11, 12, 0, 0, tzinfo=UTC)
        with patch(
            "devsecops_radar.core.sarif_export._get_safe_path",
            return_value=output.resolve(),
        ):
            with patch("devsecops_radar.core.sarif_export.datetime") as mock_dt:
                mock_dt.now.return_value = frozen_time
                export_cyclonedx(sample_findings, str(output))
        assert output.exists()
        with open(output, encoding="utf-8") as f:
            data = json.load(f)
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.5"
        assert data["metadata"]["timestamp"] == frozen_time.isoformat()
        # Components: two unique targets
        components = data["components"]
        assert len(components) == 2
        names = [c["name"] for c in components]
        assert "app/server.py" in names
        assert "other/file.py" in names
        # Vulnerabilities: 3
        vulns = data["vulnerabilities"]
        assert len(vulns) == 3
        # Severity mapping
        assert vulns[0]["ratings"][0]["severity"] == "Critical"
        assert vulns[1]["ratings"][0]["severity"] == "Low"
        assert vulns[2]["ratings"][0]["severity"] == "Info"
        # Check that two vulns affect the same component ref
        refs = [v["affects"][0]["ref"] for v in vulns]
        # refs[0] and refs[1] should be the same (app/server.py)
        assert refs[0] == refs[1]
        assert refs[2] != refs[0]

    def test_handles_write_error(self, tmp_path, sample_findings):
        output = tmp_path / "report.cdx.json"
        with patch("builtins.open", side_effect=OSError("disk full")):
            with capture_loguru() as msgs:
                export_cyclonedx(sample_findings, str(output))
            assert any("Failed to export CycloneDX report" in m for m in msgs)

    def test_empty_findings(self, tmp_path):
        output = tmp_path / "empty.cdx.json"
        with patch(
            "devsecops_radar.core.sarif_export._get_safe_path",
            return_value=output.resolve(),
        ):
            export_cyclonedx([], str(output))
        with open(output, encoding="utf-8") as f:
            data = json.load(f)
        assert data["components"] == []
        assert data["vulnerabilities"] == []
