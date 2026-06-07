import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from devsecops_radar.scanners.gitleaks import GitleaksScanner
from devsecops_radar.scanners.poutine import PoutineScanner
from devsecops_radar.scanners.semgrep import SemgrepScanner
from devsecops_radar.scanners.trivy import TrivyScanner
from devsecops_radar.scanners.zizmor import ZizmorScanner


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def write_temp_json(data):
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(data, tmp)
    tmp.close()
    return tmp.name


# ---------------------------------------------------------------------------
# TrivyScanner
# ---------------------------------------------------------------------------
class TestTrivyScanner:
    def test_valid_json(self):
        data = {
            "Results": [
                {
                    "Target": "img",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-1", "Severity": "HIGH",
                         "PkgName": "pkg", "InstalledVersion": "1.0",
                         "FixedVersion": "2.0", "Description": "desc"}
                    ]
                }
            ]
        }
        path = write_temp_json(data)
        try:
            findings = TrivyScanner().parse(path)
            assert len(findings) == 1
            assert findings[0]["severity"] == "HIGH"
            assert "desc" in findings[0]["description"]
        finally:
            Path(path).unlink()

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not json")
            path = f.name
        try:
            findings = TrivyScanner().parse(path)
            assert findings == []
        finally:
            Path(path).unlink()

    def test_missing_results(self):
        data = {"not_results": []}
        path = write_temp_json(data)
        try:
            findings = TrivyScanner().parse(path)
            assert findings == []
        finally:
            Path(path).unlink()

    def test_file_missing(self):
        findings = TrivyScanner().parse("/nonexistent/path.json")
        assert findings == []

    def test_file_too_large(self):
        data = {"Results": []}
        path = write_temp_json(data)
        try:
            # Build a realistic os.stat_result with a large size and a regular file mode
            fake_stat = os.stat_result(
                (0o100644, 0, 0, 1, 0, 0, 51 * 1024 * 1024, 0, 0, 0)
            )
            with patch.object(Path, "stat", return_value=fake_stat):
                findings = TrivyScanner().parse(path)
                assert findings == []
        finally:
            Path(path).unlink()

    def test_validate_image_target_valid(self):
        scanner = TrivyScanner()
        assert scanner._validate_image_target("nginx:latest") == "nginx:latest"
        assert scanner._validate_image_target("repo/image:tag") == "repo/image:tag"

    def test_validate_image_target_invalid_start(self):
        scanner = TrivyScanner()
        assert scanner._validate_image_target("--help") == ""

    def test_validate_image_target_invalid_chars(self):
        scanner = TrivyScanner()
        assert scanner._validate_image_target("image; rm -rf /") == ""

    def test_run_success(self):
        scanner = TrivyScanner()
        scanner._validate_image_target = MagicMock(return_value="nginx:latest")
        scanner._safe_run_command = MagicMock()
        scanner.parse = MagicMock(return_value=[{"severity": "HIGH"}])

        findings = scanner.run("nginx:latest")
        assert len(findings) == 1
        scanner._safe_run_command.assert_called_once()
        scanner.parse.assert_called_once()

    def test_run_invalid_target(self):
        scanner = TrivyScanner()
        scanner._validate_image_target = MagicMock(return_value="")
        findings = scanner.run("invalid")
        assert findings == []

    def test_run_exception(self):
        scanner = TrivyScanner()
        scanner._validate_image_target = MagicMock(return_value="nginx:latest")
        scanner._safe_run_command = MagicMock(side_effect=Exception("fail"))
        findings = scanner.run("nginx:latest")
        assert findings == []


# ---------------------------------------------------------------------------
# SemgrepScanner
# ---------------------------------------------------------------------------
class TestSemgrepScanner:
    def test_valid_json(self):
        data = {
            "results": [
                {
                    "path": "a.py",
                    "check_id": "x",
                    "extra": {"severity": "ERROR", "message": "bad"},
                    "start": {"line": 5}
                }
            ]
        }
        path = write_temp_json(data)
        try:
            findings = SemgrepScanner().parse(path)
            assert len(findings) == 1
            assert findings[0]["severity"] == "HIGH"  # ERROR -> HIGH
        finally:
            Path(path).unlink()

    def test_severity_mapping(self):
        data = {
            "results": [
                {"check_id": "warn", "extra": {"severity": "WARNING"}},
                {"check_id": "info", "extra": {"severity": "INFO"}},
                {"check_id": "unknown", "extra": {"severity": "UNKNOWN"}}
            ]
        }
        path = write_temp_json(data)
        try:
            findings = SemgrepScanner().parse(path)
            assert findings[0]["severity"] == "MEDIUM"
            assert findings[1]["severity"] == "LOW"
            assert findings[2]["severity"] == "MEDIUM"
        finally:
            Path(path).unlink()

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid")
            path = f.name
        try:
            findings = SemgrepScanner().parse(path)
            assert findings == []
        finally:
            Path(path).unlink()

    def test_missing_results(self):
        data = {"other": []}
        path = write_temp_json(data)
        try:
            findings = SemgrepScanner().parse(path)
            assert findings == []
        finally:
            Path(path).unlink()

    def test_file_too_large(self):
        data = {"results": []}
        path = write_temp_json(data)
        try:
            fake_stat = os.stat_result(
                (0o100644, 0, 0, 1, 0, 0, 51 * 1024 * 1024, 0, 0, 0)
            )
            with patch.object(Path, "stat", return_value=fake_stat):
                findings = SemgrepScanner().parse(path)
                assert findings == []
        finally:
            Path(path).unlink()

    def test_run_success(self):
        scanner = SemgrepScanner()
        scanner._validate_target_path = MagicMock(return_value="/safe/path")
        scanner._safe_run_command = MagicMock()
        scanner.parse = MagicMock(return_value=[{"severity": "HIGH"}])

        findings = scanner.run("/safe/path")
        assert len(findings) == 1
        scanner._safe_run_command.assert_called_once()
        scanner.parse.assert_called_once()

    def test_run_invalid_target(self):
        scanner = SemgrepScanner()
        scanner._validate_target_path = MagicMock(return_value="")
        findings = scanner.run("invalid")
        assert findings == []

    def test_run_exception(self):
        scanner = SemgrepScanner()
        scanner._validate_target_path = MagicMock(return_value="/safe/path")
        scanner._safe_run_command = MagicMock(side_effect=Exception("fail"))
        findings = scanner.run("/safe/path")
        assert findings == []


# ---------------------------------------------------------------------------
# PoutineScanner
# ---------------------------------------------------------------------------
class TestPoutineScanner:
    def test_valid_json(self):
        data = {
            "findings": [
                {
                    "rule_id": "x",
                    "severity": "HIGH",
                    "message": "bad",
                    "location": {"file": "f", "line": 1},
                }
            ]
        }
        path = write_temp_json(data)
        try:
            findings = PoutineScanner().parse(path)
            assert len(findings) == 1
            assert findings[0]["severity"] == "HIGH"
        finally:
            Path(path).unlink()

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid")
            path = f.name
        try:
            findings = PoutineScanner().parse(path)
            assert findings == []
        finally:
            Path(path).unlink()

    def test_file_too_large(self):
        data = {"findings": []}
        path = write_temp_json(data)
        try:
            fake_stat = os.stat_result(
                (0o100644, 0, 0, 1, 0, 0, 51 * 1024 * 1024, 0, 0, 0)
            )
            with patch.object(Path, "stat", return_value=fake_stat):
                findings = PoutineScanner().parse(path)
                assert findings == []
        finally:
            Path(path).unlink()

    def test_run_success(self):
        scanner = PoutineScanner()
        scanner._validate_target_path = MagicMock(return_value="/safe/path")
        scanner._safe_run_command = MagicMock()
        scanner.parse = MagicMock(return_value=[{"severity": "LOW"}])

        findings = scanner.run("/safe/path")
        assert len(findings) == 1
        scanner._safe_run_command.assert_called_once()
        scanner.parse.assert_called_once()

    def test_run_invalid_target(self):
        scanner = PoutineScanner()
        scanner._validate_target_path = MagicMock(return_value="")
        findings = scanner.run("invalid")
        assert findings == []

    def test_run_exception(self):
        scanner = PoutineScanner()
        scanner._validate_target_path = MagicMock(return_value="/safe/path")
        scanner._safe_run_command = MagicMock(side_effect=Exception("fail"))
        findings = scanner.run("/safe/path")
        assert findings == []


# ---------------------------------------------------------------------------
# ZizmorScanner
# ---------------------------------------------------------------------------
class TestZizmorScanner:
    def test_valid_json(self):
        data = {
            "findings": [
                {
                    "rule_id": "z1",
                    "severity": "LOW",
                    "message": "m",
                    "path": "p",
                    "location": {"line": 2},
                }
            ]
        }
        path = write_temp_json(data)
        try:
            findings = ZizmorScanner().parse(path)
            assert len(findings) == 1
            assert findings[0]["severity"] == "LOW"
        finally:
            Path(path).unlink()

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid")
            path = f.name
        try:
            findings = ZizmorScanner().parse(path)
            assert findings == []
        finally:
            Path(path).unlink()

    def test_file_too_large(self):
        data = {"findings": []}
        path = write_temp_json(data)
        try:
            fake_stat = os.stat_result(
                (0o100644, 0, 0, 1, 0, 0, 51 * 1024 * 1024, 0, 0, 0)
            )
            with patch.object(Path, "stat", return_value=fake_stat):
                findings = ZizmorScanner().parse(path)
                assert findings == []
        finally:
            Path(path).unlink()

    def test_run_success(self):
        scanner = ZizmorScanner()
        scanner._validate_target_path = MagicMock(return_value="/safe/path")
        scanner._safe_run_command = MagicMock()
        scanner.parse = MagicMock(return_value=[{"severity": "MEDIUM"}])

        findings = scanner.run("/safe/path")
        assert len(findings) == 1
        scanner._safe_run_command.assert_called_once()
        scanner.parse.assert_called_once()

    def test_run_invalid_target(self):
        scanner = ZizmorScanner()
        scanner._validate_target_path = MagicMock(return_value="")
        findings = scanner.run("invalid")
        assert findings == []

    def test_run_exception(self):
        scanner = ZizmorScanner()
        scanner._validate_target_path = MagicMock(return_value="/safe/path")
        scanner._safe_run_command = MagicMock(side_effect=Exception("fail"))
        findings = scanner.run("/safe/path")
        assert findings == []


# ---------------------------------------------------------------------------
# GitleaksScanner
# ---------------------------------------------------------------------------
class TestGitleaksScanner:
    def test_valid_list(self):
        data = [{"File": "f", "RuleID": "r", "Description": "d", "StartLine": 1}]
        path = write_temp_json(data)
        try:
            findings = GitleaksScanner().parse(path)
            assert len(findings) == 1
            assert findings[0]["severity"] == "CRITICAL"
        finally:
            Path(path).unlink()

    def test_dict_with_findings_key(self):
        data = {"Findings": [{"File": "f2", "RuleID": "r2", "Description": "d2"}]}
        path = write_temp_json(data)
        try:
            findings = GitleaksScanner().parse(path)
            assert len(findings) == 1
            assert findings[0]["target"] == "f2"
        finally:
            Path(path).unlink()

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid")
            path = f.name
        try:
            findings = GitleaksScanner().parse(path)
            assert findings == []
        finally:
            Path(path).unlink()

    def test_file_too_large(self):
        data = [{"File": "f"}]
        path = write_temp_json(data)
        try:
            fake_stat = os.stat_result(
                (0o100644, 0, 0, 1, 0, 0, 51 * 1024 * 1024, 0, 0, 0)
            )
            with patch.object(Path, "stat", return_value=fake_stat):
                findings = GitleaksScanner().parse(path)
                assert findings == []
        finally:
            Path(path).unlink()

    def test_run_success(self):
        scanner = GitleaksScanner()
        scanner._validate_target_path = MagicMock(return_value="/safe/path")
        scanner._safe_run_command = MagicMock()
        scanner.parse = MagicMock(return_value=[{"severity": "CRITICAL"}])

        findings = scanner.run("/safe/path")
        assert len(findings) == 1
        scanner._safe_run_command.assert_called_once()
        scanner.parse.assert_called_once()

    def test_run_invalid_target(self):
        scanner = GitleaksScanner()
        scanner._validate_target_path = MagicMock(return_value="")
        findings = scanner.run("invalid")
        assert findings == []

    def test_run_exception(self):
        scanner = GitleaksScanner()
        scanner._validate_target_path = MagicMock(return_value="/safe/path")
        scanner._safe_run_command = MagicMock(side_effect=Exception("fail"))
        findings = scanner.run("/safe/path")
        assert findings == []
