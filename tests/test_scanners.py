"""Tests for individual scanner implementations (Gitleaks, Poutine, Semgrep, Trivy, Zizmor)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from devsecops_radar.scanners.gitleaks import GitleaksScanner
from devsecops_radar.scanners.poutine import PoutineScanner
from devsecops_radar.scanners.semgrep import SemgrepScanner
from devsecops_radar.scanners.trivy import TrivyScanner
from devsecops_radar.scanners.zizmor import ZizmorScanner


# ---------------------------------------------------------------------------
# Sample output helpers for each scanner
# ---------------------------------------------------------------------------
def make_gitleaks_list_output():
    return [
        {
            "RuleID": "gitlab-pat",
            "File": "config.yaml",
            "StartLine": 12,
            "secret": "glpat-xxxx",
            "Description": "GitLab Personal Access Token",
        },
        {
            "RuleID": "aws-access-key",
            "File": ".env",
            "StartLine": 5,
            "Match": "AKIA1234567890ABCDEF",
            "Description": "AWS Access Key",
        },
    ]


def make_gitleaks_dict_output():
    return {
        "Findings": [
            {
                "ruleID": "generic-api-key",
                "file": "src/secrets.py",
                "line": 42,
                "description": "Generic API Key",
            }
        ]
    }


def make_poutine_output():
    return {
        "findings": [
            {
                "rule_id": "PO-001",
                "severity": "HIGH",
                "message": "Insecure pipeline configuration",
                "description": "The pipeline allows untrusted code execution.",
                "location": {"file": ".github/workflows/ci.yml", "line": 15},
            },
            {
                "rule_id": "PO-002",
                "severity": "CRITICAL",
                "message": "Secret in plain text",
                "description": "Hardcoded credential found.",
                "location": {"file": "config/deploy.env", "line": 42},
            },
        ]
    }


def make_semgrep_output():
    return {
        "results": [
            {
                "check_id": "rule-1",
                "path": "app.py",
                "start": {"line": 10},
                "extra": {"message": "XSS vulnerability", "severity": "WARNING"},
            },
            {
                "check_id": "rule-2",
                "path": "lib/ssl.so",
                "start": {"line": 20},
                "extra": {"message": "Buffer Overflow", "severity": "ERROR"},
            },
            {
                "check_id": "rule-3",
                "path": "utils.py",
                "start": {"line": 5},
                "extra": {"message": "Info message", "severity": "INFO"},
            },
        ]
    }


def make_trivy_output():
    return {
        "Results": [
            {
                "Target": "nginx:latest",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "libssl",
                        "InstalledVersion": "1.1.1",
                        "FixedVersion": "1.1.2",
                        "Severity": "CRITICAL",
                        "Title": "OpenSSL Vulnerability",
                        "Description": "A critical vulnerability in OpenSSL",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0002",
                        "PkgName": "libc",
                        "InstalledVersion": "2.31",
                        "FixedVersion": "2.32",
                        "Severity": "HIGH",
                        "Title": "libc overflow",
                        "Description": "",
                    },
                ],
            }
        ]
    }


def make_zizmor_output():
    return {
        "findings": [
            {
                "rule_id": "ZIZ-001",
                "severity": "HIGH",
                "message": "Unsafe action used",
                "description": "The action allows arbitrary code execution.",
                "path": ".github/workflows/deploy.yml",
                "location": {"file": ".github/workflows/deploy.yml", "line": 22},
            }
        ]
    }


# ---------------------------------------------------------------------------
# Helper to create a real temp file and a mock NamedTemporaryFile that points to it
# ---------------------------------------------------------------------------
def make_tmpfile_mock(fake_path, suffix=".json"):
    mock_tmp = MagicMock()
    mock_tmp.name = str(fake_path)
    mock_tmp.__enter__.return_value = mock_tmp
    mock_tmp.__exit__.return_value = None
    return mock_tmp


# ---------------------------------------------------------------------------
# Fixtures that create each scanner with a safe temporary base directory
# ---------------------------------------------------------------------------
@pytest.fixture(params=[GitleaksScanner, PoutineScanner, SemgrepScanner, ZizmorScanner])
def scanner(request, tmp_path):
    cls = request.param
    allowed_base = tmp_path / "scan_root"
    allowed_base.mkdir()
    return cls(allowed_base_dir=allowed_base)


@pytest.fixture
def trivy_scanner():
    """TrivyScanner without a base dir (image scanning doesn't require one)."""
    return TrivyScanner()


# ---------------------------------------------------------------------------
# Common parse tests (all file/path based scanners)
# ---------------------------------------------------------------------------
class TestParseCommon:
    def test_parse_path_rejected(self, scanner):
        with patch.object(scanner, "_validate_target_path", return_value=None):
            assert scanner.parse("/bad/path") == []

    def test_parse_file_not_found(self, scanner, tmp_path):
        missing = tmp_path / "missing.json"
        with patch.object(scanner, "_validate_target_path", return_value=str(missing)):
            assert scanner.parse(str(missing)) == []

    def test_parse_file_too_large(self, scanner, tmp_path):
        big = tmp_path / "big.json"
        big.write_bytes(b"x" * (51 * 1024 * 1024))  # 51 MB
        with patch.object(scanner, "_validate_target_path", return_value=str(big)):
            assert scanner.parse(str(big)) == []

    def test_parse_cannot_stat(self, scanner, tmp_path):
        f = tmp_path / "nostat.json"
        f.touch()
        # Let the file exist, but make Path.stat raise inside the try block
        with patch.object(scanner, "_validate_target_path", return_value=str(f)), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "stat", side_effect=OSError("nope")):
            assert scanner.parse(str(f)) == []

    def test_parse_invalid_json(self, scanner, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            assert scanner.parse(str(f)) == []


# ---------------------------------------------------------------------------
# Common run tests (all scanners, with special handling for Trivy)
# ---------------------------------------------------------------------------
class TestRunCommon:
    def test_run_path_rejected(self, scanner):
        with patch.object(scanner, "_validate_target_path", return_value=None):
            assert scanner.run("/bad") == []

    def test_run_success_and_calls_parse(self, scanner, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        fake_tmp = tmp_path / "fake_output.json"
        fake_tmp.write_text(json.dumps(self._make_valid_output(scanner)))

        mock_tmp = make_tmpfile_mock(fake_tmp)

        with patch.object(scanner, "_validate_target_path", return_value=str(target)), \
             patch.object(scanner, "_safe_run_command") as mock_run, \
             patch("tempfile.NamedTemporaryFile", return_value=mock_tmp), \
             patch.object(scanner, "parse", wraps=scanner.parse) as mock_parse:
            mock_run.return_value.returncode = (
                0 if isinstance(scanner, (PoutineScanner, ZizmorScanner)) else 1
            )
            scanner.run(str(target))

        mock_run.assert_called_once()
        mock_parse.assert_called_once_with(str(fake_tmp))

    def test_run_unexpected_return_code(self, scanner, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        fake_tmp = tmp_path / "output.json"
        fake_tmp.touch()

        mock_tmp = make_tmpfile_mock(fake_tmp)

        with patch.object(scanner, "_validate_target_path", return_value=str(target)), \
             patch.object(scanner, "_safe_run_command") as mock_run, \
             patch("tempfile.NamedTemporaryFile", return_value=mock_tmp):
            mock_run.return_value.returncode = 99  # unexpected
            assert scanner.run(str(target)) == []

    def test_run_exception_and_cleanup(self, scanner, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        fake_tmp = tmp_path / "output.json"
        fake_tmp.touch()

        mock_tmp = make_tmpfile_mock(fake_tmp)

        with patch.object(scanner, "_validate_target_path", return_value=str(target)), \
             patch.object(scanner, "_safe_run_command", side_effect=RuntimeError("fail")), \
             patch("tempfile.NamedTemporaryFile", return_value=mock_tmp):
            assert scanner.run(str(target)) == []
        # The real file is deleted because the finally block calls outfile.unlink()
        # on a Path constructed from mock_tmp.name (the real file path)
        assert not fake_tmp.exists()

    @staticmethod
    def _make_valid_output(scanner):
        if isinstance(scanner, GitleaksScanner):
            return make_gitleaks_list_output()
        if isinstance(scanner, PoutineScanner):
            return make_poutine_output()
        if isinstance(scanner, SemgrepScanner):
            return make_semgrep_output()
        if isinstance(scanner, ZizmorScanner):
            return make_zizmor_output()
        return {}


# ---------------------------------------------------------------------------
# Trivy-specific run tests (image validation)
# ---------------------------------------------------------------------------
class TestTrivyRun:
    def test_run_image_rejected(self, trivy_scanner):
        with patch.object(trivy_scanner, "_validate_image_target", return_value=""):
            assert trivy_scanner.run("--invalid") == []

    def test_run_success(self, trivy_scanner, tmp_path):
        fake_tmp = tmp_path / "trivy_out.json"
        fake_tmp.write_text(json.dumps(make_trivy_output()))

        mock_tmp = make_tmpfile_mock(fake_tmp)

        with patch.object(trivy_scanner, "_validate_image_target", return_value="nginx:latest"), \
             patch.object(trivy_scanner, "_safe_run_command") as mock_run, \
             patch("tempfile.NamedTemporaryFile", return_value=mock_tmp), \
             patch.object(trivy_scanner, "_validate_target_path", return_value=str(fake_tmp)), \
             patch.object(trivy_scanner, "parse", wraps=trivy_scanner.parse) as mock_parse:
            mock_run.return_value.returncode = 0
            result = trivy_scanner.run("nginx:latest")

        mock_run.assert_called_once()
        mock_parse.assert_called_once_with(str(fake_tmp))
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Trivy _validate_image_target tests
# ---------------------------------------------------------------------------
class TestTrivyImageValidation:
    @pytest.mark.parametrize(
        "target,expected",
        [
            ("nginx:latest", "nginx:latest"),
            ("ubuntu@sha256:abc123", "ubuntu@sha256:abc123"),
            ("myrepo/myimage:1.0", "myrepo/myimage:1.0"),
        ],
    )
    def test_valid_images(self, trivy_scanner, target, expected):
        assert trivy_scanner._validate_image_target(target) == expected

    @pytest.mark.parametrize(
        "target",
        [
            "--help",
            "image; rm -rf /",
            "nginx:latest@sha256:abc@extra",
            "@sha256:abc",
            "",
        ],
    )
    def test_invalid_images(self, trivy_scanner, target):
        assert trivy_scanner._validate_image_target(target) == ""


# ---------------------------------------------------------------------------
# Scanner-specific parse tests
# ---------------------------------------------------------------------------
class TestGitleaksParse:
    @pytest.fixture
    def scanner(self, tmp_path):
        allowed_base = tmp_path / "scan_root"
        allowed_base.mkdir()
        return GitleaksScanner(allowed_base_dir=allowed_base)

    def test_list_format(self, scanner, tmp_path):
        f = tmp_path / "report.json"
        f.write_text(json.dumps(make_gitleaks_list_output()))
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            findings = scanner.parse(str(f))
        assert len(findings) == 2
        assert findings[0]["id"] == "gitlab-pat"
        assert findings[0]["severity"] == "CRITICAL"
        assert "redacted" in findings[0]["description"].lower()
        assert findings[1]["id"] == "aws-access-key"

    def test_dict_format(self, scanner, tmp_path):
        f = tmp_path / "report.json"
        f.write_text(json.dumps(make_gitleaks_dict_output()))
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            findings = scanner.parse(str(f))
        assert len(findings) == 1
        assert findings[0]["id"] == "generic-api-key"
        assert findings[0]["line"] == 42


class TestPoutineParse:
    @pytest.fixture
    def scanner(self, tmp_path):
        allowed_base = tmp_path / "scan_root"
        allowed_base.mkdir()
        return PoutineScanner(allowed_base_dir=allowed_base)

    def test_valid_report(self, scanner, tmp_path):
        f = tmp_path / "poutine.json"
        f.write_text(json.dumps(make_poutine_output()))
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            findings = scanner.parse(str(f))
        assert len(findings) == 2
        assert findings[0]["id"] == "PO-001"
        assert findings[0]["line"] == 15
        assert findings[1]["severity"] == "CRITICAL"

    def test_missing_location(self, scanner, tmp_path):
        data = {"findings": [{"rule_id": "R1", "severity": "LOW", "message": "test"}]}
        f = tmp_path / "noloc.json"
        f.write_text(json.dumps(data))
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            findings = scanner.parse(str(f))
        assert findings[0]["target"] == ""
        assert findings[0]["line"] is None


class TestSemgrepParse:
    @pytest.fixture
    def scanner(self, tmp_path):
        allowed_base = tmp_path / "scan_root"
        allowed_base.mkdir()
        return SemgrepScanner(allowed_base_dir=allowed_base)

    def test_valid_report(self, scanner, tmp_path):
        f = tmp_path / "semgrep.json"
        f.write_text(json.dumps(make_semgrep_output()))
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            findings = scanner.parse(str(f))
        assert len(findings) == 3
        assert findings[0]["severity"] == "MEDIUM"  # WARNING -> MEDIUM
        assert findings[1]["severity"] == "HIGH"  # ERROR -> HIGH
        assert findings[2]["severity"] == "LOW"  # INFO -> LOW
        assert findings[0]["line"] == 10

    def test_no_results_key(self, scanner, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text('{"other": []}')
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            assert scanner.parse(str(f)) == []

    def test_skips_invalid_items(self, scanner, tmp_path):
        f = tmp_path / "mixed.json"
        f.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "ok",
                            "path": "a.py",
                            "start": {"line": 1},
                            "extra": {"message": "m", "severity": "INFO"},
                        },
                        "not a dict",
                    ]
                }
            )
        )
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            findings = scanner.parse(str(f))
        assert len(findings) == 1


class TestTrivyParse:
    @pytest.fixture
    def scanner(self, trivy_scanner):
        return trivy_scanner

    def test_valid_report(self, scanner, tmp_path):
        f = tmp_path / "trivy.json"
        f.write_text(json.dumps(make_trivy_output()))
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            findings = scanner.parse(str(f))
        assert len(findings) == 2
        assert findings[0]["id"] == "CVE-2024-0001"
        assert findings[0]["severity"] == "CRITICAL"
        assert "Package: libssl (1.1.1)" in findings[0]["description"]
        assert "Fixed Version: 1.1.2" in findings[0]["description"]
        assert findings[0]["line"] is None
        assert findings[1]["target"] == "nginx:latest"

    def test_skips_non_dict_vulnerabilities(self, scanner, tmp_path):
        data = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-OK",
                            "PkgName": "lib",
                            "Severity": "LOW",
                            "Title": "ok",
                        },
                        "not a dict",
                    ],
                }
            ]
        }
        f = tmp_path / "mixed.json"
        f.write_text(json.dumps(data))
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            findings = scanner.parse(str(f))
        assert len(findings) == 1


class TestZizmorParse:
    @pytest.fixture
    def scanner(self, tmp_path):
        allowed_base = tmp_path / "scan_root"
        allowed_base.mkdir()
        return ZizmorScanner(allowed_base_dir=allowed_base)

    def test_valid_report(self, scanner, tmp_path):
        f = tmp_path / "zizmor.json"
        f.write_text(json.dumps(make_zizmor_output()))
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            findings = scanner.parse(str(f))
        assert len(findings) == 1
        assert findings[0]["id"] == "ZIZ-001"
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["line"] == 22

    def test_missing_location(self, scanner, tmp_path):
        data = {"findings": [{"rule_id": "Z1", "severity": "MEDIUM", "message": "test"}]}
        f = tmp_path / "noloc.json"
        f.write_text(json.dumps(data))
        with patch.object(scanner, "_validate_target_path", return_value=str(f)):
            findings = scanner.parse(str(f))
        assert findings[0]["line"] is None
