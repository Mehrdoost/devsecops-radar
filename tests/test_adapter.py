"""Tests for the ScannerAdapter class."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure env vars are set before importing models
os.environ["JWT_SECRET"] = "a" * 32
os.environ["PIPELINE_API_KEY"] = "valid-api-key"

from devsecops_radar.core.models import FindingSchema
from devsecops_radar.scanners.adapter import ScannerAdapter


@pytest.fixture
def mock_scanner():
    scanner = MagicMock()
    scanner.__class__.__name__ = "MockScanner"
    # Safe default: path validation just returns the path unchanged
    scanner._validate_target_path = lambda p: p
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
        mock_scanner._validate_target_path.return_value = None  # override default
        assert adapter.parse("/bad") == []

    def test_scanner_path_validation_accepts(self, adapter, mock_scanner, tmp_path):
        f = tmp_path / "results.json"
        f.write_text("{}")
        mock_scanner._validate_target_path.return_value = str(f)  # still returns path
        raw = [{"tool": "t", "id": "r", "severity": "LOW", "target": "t", "title": "t"}]
        mock_scanner.parse.return_value = raw
        result = adapter.parse(str(f))
        assert len(result) == 1
        assert isinstance(result[0], FindingSchema)

    def test_file_not_found(self, adapter, mock_scanner):
        # ensure path validation passes (default lambda)
        assert adapter.parse("/no/such/file") == []

    def test_file_not_readable(self, adapter, mock_scanner, tmp_path):
        f = tmp_path / "unreadable.json"
        f.write_text("{}")
        with patch("os.access", return_value=False):
            assert adapter.parse(str(f)) == []

    def test_file_too_large(self, adapter, mock_scanner, tmp_path):
        f = tmp_path / "large.json"
        f.write_bytes(b"x" * (51 * 1024 * 1024))
        assert adapter.parse(str(f)) == []

    def test_cannot_stat(self, adapter, mock_scanner, tmp_path):
        f = tmp_path / "nostat.json"
        with patch.object(Path, "stat", side_effect=OSError("nope")):
            assert adapter.parse(str(f)) == []

    def test_scanner_parse_exception(self, adapter, mock_scanner, tmp_path):
        f = tmp_path / "ok.json"
        f.write_text("{}")
        # default pass-through path validation is already set
        mock_scanner.parse.side_effect = RuntimeError("parse failed")
        assert adapter.parse(str(f)) == []


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
class TestRun:
    def test_success(self, adapter, mock_scanner):
        raw = [{"tool": "t", "id": "r", "severity": "LOW", "target": "t", "title": "t"}]
        mock_scanner.run.return_value = raw
        result = adapter.run("target")
        assert len(result) == 1
        assert isinstance(result[0], FindingSchema)

    def test_exception(self, adapter, mock_scanner):
        mock_scanner.run.side_effect = RuntimeError("fail")
        assert adapter.run("target") == []
