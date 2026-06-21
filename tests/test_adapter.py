"""Tests for the ScannerAdapter class – final version (fixed hasattr issue)."""

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ["JWT_SECRET"] = "a" * 32
os.environ["PIPELINE_API_KEY"] = "valid-api-key"

from devsecops_radar.core.models import FindingSchema
from devsecops_radar.scanners.adapter import ScannerAdapter


@pytest.fixture
def mock_scanner():
    scanner = MagicMock()
    scanner.__class__.__name__ = "MockScanner"
    scanner._validate_target_path = lambda p: p
    # By default, _validate_findings should pass through findings unchanged,
    # otherwise MagicMock's auto‑created attribute returns a MagicMock object.
    scanner._validate_findings = lambda x: x
    return scanner


@pytest.fixture
def adapter(mock_scanner):
    return ScannerAdapter(mock_scanner)


# ---------------------------------------------------------------------------
# _safe_map_to_schema
# ---------------------------------------------------------------------------
class TestSafeMapToSchema:
    def test_non_list_returns_empty(self, adapter):
        assert adapter._safe_map_to_schema({"not": "list"}) == []
        assert adapter._safe_map_to_schema("string") == []
        assert adapter._safe_map_to_schema(None) == []

    def test_empty_list(self, adapter):
        assert adapter._safe_map_to_schema([]) == []

    def test_all_valid(self, adapter):
        raw = [
            {"tool": "semgrep", "id": "r1", "severity": "HIGH", "target": "a.py", "title": "SQLi"},
            {"tool": "trivy", "id": "CVE-123", "severity": "CRITICAL", "target": "lib.so", "title": "Overflow"},
        ]
        result = adapter._safe_map_to_schema(raw)
        assert len(result) == 2
        assert isinstance(result[0], FindingSchema)
        assert result[1].severity == "CRITICAL"

    def test_mixed_valid_invalid(self, adapter):
        raw = [
            {"tool": "t", "id": "ok", "severity": "LOW", "target": "t", "title": "t"},
            {"tool": "", "id": "bad", "severity": "LOW", "target": "t", "title": "t"},
            {"tool": "t", "severity": "LOW", "target": "t", "title": "t"},
        ]
        result = adapter._safe_map_to_schema(raw)
        assert len(result) == 1
        assert result[0].id == "ok"

    def test_all_invalid(self, adapter):
        raw = [{"tool": ""}, {"id": "x"}]
        assert adapter._safe_map_to_schema(raw) == []

    def test_unexpected_exception(self, adapter):
        raw = [{"tool": "t", "id": "x", "severity": "LOW", "target": "t", "title": "t"}]
        with patch("devsecops_radar.scanners.adapter.FindingSchema", side_effect=RuntimeError("oops")):
            assert adapter._safe_map_to_schema(raw) == []


# ---------------------------------------------------------------------------
# parse
# ---------------------------------------------------------------------------
class TestParse:
    def test_scanner_path_validation_rejects(self, adapter, mock_scanner):
        mock_scanner._validate_target_path.return_value = None
        assert adapter.parse("/bad") == []

    def test_scanner_path_validation_accepts(self, adapter, mock_scanner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "results.json"
        f.write_text("{}")
        mock_scanner._validate_target_path.return_value = str(f)
        raw = [{"tool": "t", "id": "r", "severity": "LOW", "target": "t", "title": "t"}]
        # Replace parse with a dedicated mock that returns a list
        mock_scanner.parse = MagicMock(return_value=raw)
        result = adapter.parse(str(f))
        assert len(result) == 1
        assert isinstance(result[0], FindingSchema)

    def test_file_not_found(self, adapter, mock_scanner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        missing = tmp_path / "missing.json"
        assert adapter.parse(str(missing)) == []

    def test_file_not_readable(self, adapter, mock_scanner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "unreadable.json"
        f.write_text("{}")
        with patch("devsecops_radar.scanners.adapter.safe_read_open", side_effect=PermissionError):
            assert adapter.parse(str(f)) == []

    def test_file_too_large(self, adapter, mock_scanner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "large.json"
        f.write_bytes(b"x" * (51 * 1024 * 1024))
        assert adapter.parse(str(f)) == []

    def test_cannot_stat(self, adapter, mock_scanner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "nostat.json"
        f.write_text("{}")
        with patch("os.fstat", side_effect=OSError("nope")):
            assert adapter.parse(str(f)) == []

    def test_scanner_parse_exception(self, adapter, mock_scanner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "ok.json"
        f.write_text("{}")
        mock_scanner.parse.side_effect = RuntimeError("parse failed")
        assert adapter.parse(str(f)) == []

    def test_scanner_with_validate_findings(self, adapter, mock_scanner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "results.json"
        f.write_text("{}")
        mock_scanner._validate_target_path.return_value = str(f)
        raw = [
            {"tool": "t", "id": "r", "severity": "LOW", "target": "t", "title": "t"},
            {"tool": ""},
        ]
        # Override _validate_findings to filter out invalid entries
        mock_scanner._validate_findings = lambda data: [d for d in data if d.get("tool")]
        mock_scanner.parse = MagicMock(return_value=raw)
        result = adapter.parse(str(f))
        assert len(result) == 1


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
class TestRun:
    def test_success(self, adapter, mock_scanner):
        raw = [{"tool": "t", "id": "r", "severity": "LOW", "target": "t", "title": "t"}]
        mock_scanner.run = MagicMock(return_value=raw)
        result = adapter.run("target")
        assert len(result) == 1
        assert isinstance(result[0], FindingSchema)

    def test_exception(self, adapter, mock_scanner):
        mock_scanner.run.side_effect = RuntimeError("fail")
        assert adapter.run("target") == []

    def test_with_validate_findings(self, adapter, mock_scanner):
        raw = [
            {"tool": "t", "id": "r", "severity": "LOW", "target": "t", "title": "t"},
            {"tool": ""},
        ]
        mock_scanner._validate_findings = lambda data: [d for d in data if d.get("tool")]
        mock_scanner.run = MagicMock(return_value=raw)
        result = adapter.run("target")
        assert len(result) == 1
