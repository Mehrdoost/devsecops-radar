"""Tests for SARIF and CycloneDX exports."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from devsecops_radar.core.sarif_export import export_cyclonedx, export_sarif

SAMPLE_FINDINGS = [
    {"id": "CVE-2024-001", "severity": "CRITICAL", "target": "app/server.py", "description": "RCE"},
    {"id": "CVE-2024-002", "severity": "low", "target": "app/server.py", "description": "Info"},
    {"id": "CVE-2024-003", "severity": "unknown", "target": "other/file.py"},
]


def _mock_atomic_write():
    f = StringIO()
    mgr = MagicMock()
    mgr.__enter__.return_value = f
    mgr.__exit__.return_value = None
    return mgr, f


class TestExportSarif:
    def test_creates_valid_sarif(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        output = tmp_path / "report.sarif"
        monkeypatch.setattr(
            "devsecops_radar.core.sarif_export.resolve_safe_path",
            lambda p, base_dir=None: Path(p).resolve(),
        )
        mgr, f = _mock_atomic_write()
        with patch("devsecops_radar.core.sarif_export.atomic_write", return_value=mgr):
            export_sarif(SAMPLE_FINDINGS, str(output))
        data = json.loads(f.getvalue())
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 3

    def test_handles_write_error(self, tmp_path: Path) -> None:
        output = tmp_path / "report.sarif"
        with patch("devsecops_radar.core.sarif_export.atomic_write",
                   side_effect=OSError):
            with patch("devsecops_radar.core.sarif_export.logger") as mock_log:
                export_sarif(SAMPLE_FINDINGS, str(output))
                mock_log.error.assert_called_once()

    def test_empty_findings(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        output = tmp_path / "empty.sarif"
        monkeypatch.setattr(
            "devsecops_radar.core.sarif_export.resolve_safe_path",
            lambda p, base_dir=None: Path(p).resolve(),
        )
        mgr, f = _mock_atomic_write()
        with patch("devsecops_radar.core.sarif_export.atomic_write", return_value=mgr):
            export_sarif([], str(output))
        data = json.loads(f.getvalue())
        assert len(data["runs"][0]["results"]) == 0


class TestExportCycloneDX:
    def test_creates_valid_cyclonedx(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        output = tmp_path / "report.cdx.json"
        frozen_time = datetime(2025, 6, 11, 12, 0, 0, tzinfo=UTC)
        mgr, f = _mock_atomic_write()
        with patch("devsecops_radar.core.sarif_export.datetime") as mock_dt, \
                patch("devsecops_radar.core.sarif_export.atomic_write", return_value=mgr):
            mock_dt.now.return_value = frozen_time
            export_cyclonedx(SAMPLE_FINDINGS, str(output))
        data = json.loads(f.getvalue())
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.5"
        assert data["metadata"]["timestamp"] == frozen_time.isoformat()
        components = data["components"]
        assert len(components) == 2
        names = [c["name"] for c in components]
        assert "server.py" in names
        assert "file.py" in names

    def test_handles_write_error(self, tmp_path: Path) -> None:
        output = tmp_path / "report.cdx.json"
        with patch("devsecops_radar.core.sarif_export.atomic_write",
                   side_effect=OSError):
            with patch("devsecops_radar.core.sarif_export.logger") as mock_log:
                export_cyclonedx(SAMPLE_FINDINGS, str(output))
                mock_log.error.assert_called_once()

    def test_empty_findings(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        output = tmp_path / "empty.cdx.json"
        monkeypatch.chdir(tmp_path)
        mgr, f = _mock_atomic_write()
        with patch("devsecops_radar.core.sarif_export.atomic_write", return_value=mgr):
            export_cyclonedx([], str(output))
        data = json.loads(f.getvalue())
        assert len(data["components"]) == 0
