import urllib.parse
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from devsecops_radar.core.sarif_export import (
    _get_safe_path,
    _safe_int,
    export_cyclonedx,
    export_sarif,
    logger,
)


# ------------------------------------------------------------
# _safe_int
# ------------------------------------------------------------
class TestSafeInt:
    def test_positive_int(self):
        assert _safe_int(42) == 42

    def test_zero_returns_default(self):
        assert _safe_int(0) == 1

    def test_negative_returns_default(self):
        assert _safe_int(-5) == 1

    def test_none_returns_default(self):
        assert _safe_int(None) == 1

    def test_invalid_string_returns_default(self):
        assert _safe_int("abc") == 1

    def test_float_truncates_to_int(self):
        # int(3.9) = 3, positive
        assert _safe_int(3.9) == 3

    def test_string_digit(self):
        assert _safe_int("10") == 10


# ------------------------------------------------------------
# _get_safe_path
# ------------------------------------------------------------
class TestGetSafePath:
    def test_valid_path(self):
        # default base is cwd, but we'll mock to avoid real paths
        with patch.object(Path, "resolve") as mock_resolve:
            base = Path("/safe")
            target = base / "report.sarif"
            mock_resolve.side_effect = [base, target]  # first base.resolve(), then target.resolve()
            result = _get_safe_path("report.sarif", allowed_dir="/safe")
            assert result == target

    def test_path_traversal_blocked(self):
        with pytest.raises(ValueError, match="Security Violation"):
            _get_safe_path("../etc/passwd", allowed_dir="/safe")

    def test_default_allowed_dir(self):
        # Without allowed_dir, uses cwd. We'll mock cwd and resolve.
        with patch.object(Path, "resolve") as mock_resolve:
            cwd = Path("/current")
            target = cwd / "out.json"
            mock_resolve.side_effect = [cwd, target]
            result = _get_safe_path("out.json")
            assert result == target


# ------------------------------------------------------------
# export_sarif
# ------------------------------------------------------------
class TestExportSarif:
    @pytest.fixture
    def mock_open_file(self):
        return mock_open()

    @pytest.fixture
    def safe_path(self):
        return Path("/safe/report.sarif")

    def test_successful_export(self, safe_path, mock_open_file):
        findings = [
            {"id": "R1", "title": "SQLi", "description": "desc1", "target": "app.py", "line": 42},
            {"id": "R1", "title": "SQLi Dup", "target": "app.py", "line": 10},  # same rule
            {"id": "R2", "title": "XSS", "target": "views/login.html", "line": "abc"},  # invalid line -> default 1
        ]
        with patch("devsecops_radar.core.sarif_export._get_safe_path", return_value=safe_path), \
             patch("builtins.open", mock_open_file), \
             patch.object(logger, "success"):

            export_sarif(findings, "report.sarif")

            # Verify file was written
            mock_open_file.assert_called_once_with(safe_path, "w", encoding="utf-8")
            # Get written data
            mock_open_file()
            # json.dump writes two args: data, file handle
            # So handle.write was not called directly, but json.dump uses the file handle.
            # To inspect, we can capture the data passed to json.dump via a mock.
            # Instead, we'll use a different approach: mock json.dump itself.
            # Let's restructure: patch json.dump and verify the data structure.

    def test_sarif_structure(self, safe_path):
        findings = [
            {"id": "R1", "title": "T1", "description": "D1", "target": "file.py", "line": 5},
            {"id": "R2", "target": "../etc/passwd", "line": 0, "description": "desc2"},  # unsafe line -> default 1, target URL-encoded
        ]
        with patch("devsecops_radar.core.sarif_export._get_safe_path", return_value=safe_path), \
             patch("builtins.open", mock_open()), \
             patch("json.dump") as mock_json_dump, \
             patch.object(logger, "success"):
            export_sarif(findings, "out.sarif")

            # Verify that json.dump was called once
            mock_json_dump.assert_called_once()
            data = mock_json_dump.call_args[0][0]  # first argument

            # Check top-level keys
            assert data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
            assert data["version"] == "2.1.0"
            assert "runs" in data
            run = data["runs"][0]
            assert run["tool"]["driver"]["name"] == "Pipeline Sentinel"

            # Rules
            rules_list = run["tool"]["driver"]["rules"]
            assert len(rules_list) == 2
            rule_ids = {r["id"] for r in rules_list}
            assert rule_ids == {"R1", "R2"}

            # Results
            results = run["results"]
            assert len(results) == 2
            # Check first result
            res1 = results[0]
            assert res1["ruleId"] == "R1"
            assert res1["locations"][0]["physicalLocation"]["region"]["startLine"] == 5
            assert res1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "file.py"

            # Second result: line was 0 -> default 1
            res2 = results[1]
            assert res2["ruleId"] == "R2"
            assert res2["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
            # URI encoding for "../etc/passwd"
            encoded_target = urllib.parse.quote("../etc/passwd", safe="/:")
            assert res2["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == encoded_target

            mock_success = logger.success
            mock_success.assert_called_once_with(f"SARIF report successfully exported to {safe_path}")

    def test_path_traversal_error(self):
        with patch("devsecops_radar.core.sarif_export._get_safe_path", side_effect=ValueError("traversal")), \
             patch.object(logger, "error") as mock_error:
            export_sarif([{"id": "1"}], "bad.sarif")
            mock_error.assert_called_once()

    def test_generic_exception(self, safe_path):
        findings = [{"id": "1"}]
        with patch("devsecops_radar.core.sarif_export._get_safe_path", return_value=safe_path), \
             patch("builtins.open", side_effect=Exception("disk full")), \
             patch.object(logger, "error") as mock_error:
            export_sarif(findings, "output.sarif")
            mock_error.assert_called_once()
            assert "Failed to export SARIF report" in mock_error.call_args[0][0]


# ------------------------------------------------------------
# export_cyclonedx
# ------------------------------------------------------------
class TestExportCycloneDX:
    @pytest.fixture
    def safe_path(self):
        return Path("/safe/report.cdx.json")

    def test_successful_export(self, safe_path):
        findings = [
            {"id": "CVE-1", "severity": "HIGH", "target": "file1.py", "description": "desc1"},
            {"id": "CVE-2", "severity": "CRITICAL", "target": "file1.py", "description": "desc2"},  # same target, same component
            {"id": "CVE-3", "severity": "UNKNOWN", "target": "file2.py", "description": ""},
        ]
        with patch("devsecops_radar.core.sarif_export._get_safe_path", return_value=safe_path), \
             patch("builtins.open", mock_open()), \
             patch("json.dump") as mock_json_dump, \
             patch("devsecops_radar.core.sarif_export.datetime") as mock_datetime, \
             patch.object(logger, "success") as mock_success:

            mock_datetime.utcnow.return_value.isoformat.return_value = "2025-01-01T00:00:00"
            export_cyclonedx(findings, "out.cdx.json")

            mock_json_dump.assert_called_once()
            data = mock_json_dump.call_args[0][0]

            # Check metadata
            assert data["bomFormat"] == "CycloneDX"
            assert data["specVersion"] == "1.5"
            assert data["version"] == 1
            assert data["metadata"]["timestamp"] == "2025-01-01T00:00:00Z"

            # Components: should be 2 unique files
            components = data["components"]
            assert len(components) == 2
            comp_names = {c["name"] for c in components}
            assert comp_names == {"file1.py", "file2.py"}

            # Vulnerabilities
            vulns = data["vulnerabilities"]
            assert len(vulns) == 3
            # Check severity mapping
            sev_map = {v["id"]: v["ratings"][0]["severity"] for v in vulns}
            assert sev_map["CVE-1"] == "High"
            assert sev_map["CVE-2"] == "Critical"
            assert sev_map["CVE-3"] == "Info"

            # Check that each vulnerability affects the correct component ref
            # bom-ref format: pkg:file/<encoded>
            expected_ref1 = "pkg:file/" + urllib.parse.quote("file1.py", safe='')
            expected_ref2 = "pkg:file/" + urllib.parse.quote("file2.py", safe='')
            assert vulns[0]["affects"][0]["ref"] == expected_ref1
            assert vulns[1]["affects"][0]["ref"] == expected_ref1
            assert vulns[2]["affects"][0]["ref"] == expected_ref2

            mock_success.assert_called_once_with(f"CycloneDX report successfully exported to {safe_path}")

    def test_path_traversal_error(self):
        with patch("devsecops_radar.core.sarif_export._get_safe_path", side_effect=ValueError("traversal")), \
             patch.object(logger, "error") as mock_error:
            export_cyclonedx([{"id": "1"}], "bad.cdx.json")
            mock_error.assert_called_once()

    def test_generic_exception(self, safe_path):
        findings = [{"id": "1"}]
        with patch("devsecops_radar.core.sarif_export._get_safe_path", return_value=safe_path), \
             patch("builtins.open", side_effect=Exception("io error")), \
             patch.object(logger, "error") as mock_error:
            export_cyclonedx(findings, "out.cdx.json")
            mock_error.assert_called_once()
            assert "Failed to export CycloneDX report" in mock_error.call_args[0][0]
