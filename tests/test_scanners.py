"""Tests for individual scanner implementations (updated for mkstemp + safe_read_open)."""

import json
from unittest.mock import patch

import pytest

from devsecops_radar.scanners.gitleaks import GitleaksScanner
from devsecops_radar.scanners.poutine import PoutineScanner
from devsecops_radar.scanners.semgrep import SemgrepScanner
from devsecops_radar.scanners.trivy import TrivyScanner
from devsecops_radar.scanners.zizmor import ZizmorScanner


# ---------------------------------------------------------------------------
# Sample output helpers
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
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(params=[GitleaksScanner, PoutineScanner, SemgrepScanner, ZizmorScanner])
def scanner(request, tmp_path):
    """Create scanner with a safe base directory inside tmp_path."""
    cls = request.param
    allowed_base = tmp_path / "scan_root"
    allowed_base.mkdir()
    return cls(allowed_base_dir=allowed_base)


@pytest.fixture
def trivy_scanner(tmp_path):
    """TrivyScanner with a dedicated base dir for test isolation."""
    base = tmp_path / "trivy_base"
    base.mkdir()
    return TrivyScanner(allowed_base_dir=base)


# ---------------------------------------------------------------------------
# Common parse tests
# ---------------------------------------------------------------------------
class TestParseCommon:
    def test_parse_path_rejected(self, scanner):
        # path outside allowed_base_dir -> safe_read_open raises ValueError
        with patch("devsecops_radar.core.path_security.resolve_safe_path",
                   side_effect=ValueError("outside allowed")):
            assert scanner.parse("/bad/path") == []

    def test_parse_file_not_found(self, scanner):
        missing = str(scanner.allowed_base_dir / "missing.json")
        assert scanner.parse(missing) == []

    def test_parse_file_too_large(self, scanner):
        big = scanner.allowed_base_dir / "big.json"
        big.write_bytes(b"x" * (51 * 1024 * 1024))  # 51 MB
        assert scanner.parse(str(big)) == []

    def test_parse_cannot_stat(self, scanner):
        f = scanner.allowed_base_dir / "nostat.json"
        f.write_text("[]")
        # Make fstat fail inside safe_read_open
        with patch("os.fstat", side_effect=OSError("nope")):
            assert scanner.parse(str(f)) == []

    def test_parse_invalid_json(self, scanner):
        f = scanner.allowed_base_dir / "bad.json"
        f.write_text("not json")
        assert scanner.parse(str(f)) == []


# ---------------------------------------------------------------------------
# Common run tests
# ---------------------------------------------------------------------------
class TestRunCommon:
    def test_run_path_rejected(self, scanner):
        with patch.object(scanner, "_validate_target_path", return_value=None):
            assert scanner.run("/bad") == []

    def test_run_success_and_calls_parse(self, scanner):
        target_dir = scanner.allowed_base_dir / "repo"
        target_dir.mkdir()

        # Create a known output file inside allowed_base_dir
        out_path = scanner.allowed_base_dir / "output.json"
        out_path.write_text(json.dumps(self._make_valid_output(scanner)))

        mock_fd = 999  # arbitrary
        with patch("tempfile.mkstemp", return_value=(mock_fd, str(out_path))), \
             patch("os.close"), \
             patch.object(scanner, "_validate_target_path", return_value=str(target_dir)), \
             patch.object(scanner, "_safe_run_command") as mock_run, \
             patch.object(scanner, "parse", wraps=scanner.parse) as mock_parse:

            mock_run.return_value.returncode = (
                0 if isinstance(scanner, (PoutineScanner, ZizmorScanner)) else 1
            )
            scanner.run(str(target_dir))

        mock_run.assert_called_once()
        mock_parse.assert_called_once_with(str(out_path))

    def test_run_unexpected_return_code(self, scanner):
        target = scanner.allowed_base_dir / "repo"
        target.mkdir()

        out_path = scanner.allowed_base_dir / "output.json"
        out_path.write_text("[]")

        with patch("tempfile.mkstemp", return_value=(1, str(out_path))), \
             patch("os.close"), \
             patch.object(scanner, "_validate_target_path", return_value=str(target)), \
             patch.object(scanner, "_safe_run_command") as mock_run:
            mock_run.return_value.returncode = 99  # unexpected
            assert scanner.run(str(target)) == []

    def test_run_exception_and_cleanup(self, scanner):
        target = scanner.allowed_base_dir / "repo"
        target.mkdir()

        out_path = scanner.allowed_base_dir / "output.json"
        out_path.write_text("[]")

        with patch("tempfile.mkstemp", return_value=(1, str(out_path))), \
             patch("os.close"), \
             patch.object(scanner, "_validate_target_path", return_value=str(target)), \
             patch.object(scanner, "_safe_run_command", side_effect=RuntimeError("fail")):
            assert scanner.run(str(target)) == []

        # The finally block should delete the real output file
        assert not out_path.exists()

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
# Trivy-specific run tests
# ---------------------------------------------------------------------------
class TestTrivyRun:
    def test_run_image_rejected(self, trivy_scanner):
        with patch.object(trivy_scanner, "_validate_image_target", return_value=""):
            assert trivy_scanner.run("--invalid") == []

    def test_run_success(self, trivy_scanner):
        # Trivy uses the scanner's allowed_base_dir for temporary output
        out_path = trivy_scanner.allowed_base_dir / "trivy_out.json"
        out_path.write_text(json.dumps(make_trivy_output()))

        with patch("tempfile.mkstemp", return_value=(1, str(out_path))), \
             patch("os.close"), \
             patch.object(trivy_scanner, "_validate_image_target", return_value="nginx:latest"), \
             patch.object(trivy_scanner, "_safe_run_command") as mock_run, \
             patch.object(trivy_scanner, "parse", wraps=trivy_scanner.parse) as mock_parse:
            mock_run.return_value.returncode = 0
            result = trivy_scanner.run("nginx:latest")

        mock_run.assert_called_once()
        mock_parse.assert_called_once_with(str(out_path))
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Trivy _validate_image_target
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
# Scanner-specific parse tests (files created inside allowed_base_dir)
# ---------------------------------------------------------------------------
class TestGitleaksParse:
    @pytest.fixture
    def scanner(self, tmp_path):
        base = tmp_path / "scan_root"
        base.mkdir()
        return GitleaksScanner(allowed_base_dir=base)

    def test_list_format(self, scanner):
        f = scanner.allowed_base_dir / "report.json"
        f.write_text(json.dumps(make_gitleaks_list_output()))
        findings = scanner.parse(str(f))
        assert len(findings) == 2
        assert findings[0]["id"] == "gitlab-pat"
        assert findings[0]["severity"] == "CRITICAL"
        assert "redacted" in findings[0]["description"].lower()
        assert findings[1]["id"] == "aws-access-key"

    def test_dict_format(self, scanner):
        f = scanner.allowed_base_dir / "report.json"
        f.write_text(json.dumps(make_gitleaks_dict_output()))
        findings = scanner.parse(str(f))
        assert len(findings) == 1
        assert findings[0]["id"] == "generic-api-key"
        assert findings[0]["line"] == 42


class TestPoutineParse:
    @pytest.fixture
    def scanner(self, tmp_path):
        base = tmp_path / "scan_root"
        base.mkdir()
        return PoutineScanner(allowed_base_dir=base)

    def test_valid_report(self, scanner):
        f = scanner.allowed_base_dir / "poutine.json"
        f.write_text(json.dumps(make_poutine_output()))
        findings = scanner.parse(str(f))
        assert len(findings) == 2
        assert findings[0]["id"] == "PO-001"
        assert findings[0]["line"] == 15
        assert findings[1]["severity"] == "CRITICAL"

    def test_missing_location(self, scanner):
        data = {"findings": [{"rule_id": "R1", "severity": "LOW", "message": "test"}]}
        f = scanner.allowed_base_dir / "noloc.json"
        f.write_text(json.dumps(data))
        findings = scanner.parse(str(f))
        assert findings[0]["target"] == ""
        assert findings[0]["line"] is None


class TestSemgrepParse:
    @pytest.fixture
    def scanner(self, tmp_path):
        base = tmp_path / "scan_root"
        base.mkdir()
        return SemgrepScanner(allowed_base_dir=base)

    def test_valid_report(self, scanner):
        f = scanner.allowed_base_dir / "semgrep.json"
        f.write_text(json.dumps(make_semgrep_output()))
        findings = scanner.parse(str(f))
        assert len(findings) == 3
        assert findings[0]["severity"] == "MEDIUM"  # WARNING -> MEDIUM
        assert findings[1]["severity"] == "HIGH"  # ERROR -> HIGH
        assert findings[2]["severity"] == "LOW"  # INFO -> LOW
        assert findings[0]["line"] == 10

    def test_no_results_key(self, scanner):
        f = scanner.allowed_base_dir / "empty.json"
        f.write_text('{"other": []}')
        assert scanner.parse(str(f)) == []

    def test_skips_invalid_items(self, scanner):
        f = scanner.allowed_base_dir / "mixed.json"
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
        findings = scanner.parse(str(f))
        assert len(findings) == 1


class TestTrivyParse:
    @pytest.fixture
    def scanner(self, trivy_scanner):
        return trivy_scanner

    def test_valid_report(self, scanner):
        f = scanner.allowed_base_dir / "trivy.json"
        f.write_text(json.dumps(make_trivy_output()))
        findings = scanner.parse(str(f))
        assert len(findings) == 2
        assert findings[0]["id"] == "CVE-2024-0001"
        assert findings[0]["severity"] == "CRITICAL"
        assert "Package: libssl (1.1.1)" in findings[0]["description"]
        assert "Fixed Version: 1.1.2" in findings[0]["description"]
        assert findings[0]["line"] is None
        assert findings[1]["target"] == "nginx:latest"

    def test_skips_non_dict_vulnerabilities(self, scanner):
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
        f = scanner.allowed_base_dir / "mixed.json"
        f.write_text(json.dumps(data))
        findings = scanner.parse(str(f))
        assert len(findings) == 1


class TestZizmorParse:
    @pytest.fixture
    def scanner(self, tmp_path):
        base = tmp_path / "scan_root"
        base.mkdir()
        return ZizmorScanner(allowed_base_dir=base)

    def test_valid_report(self, scanner):
        f = scanner.allowed_base_dir / "zizmor.json"
        f.write_text(json.dumps(make_zizmor_output()))
        findings = scanner.parse(str(f))
        assert len(findings) == 1
        assert findings[0]["id"] == "ZIZ-001"
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["line"] == 22

    def test_missing_location(self, scanner):
        data = {"findings": [{"rule_id": "Z1", "severity": "MEDIUM", "message": "test"}]}
        f = scanner.allowed_base_dir / "noloc.json"
        f.write_text(json.dumps(data))
        findings = scanner.parse(str(f))
        assert findings[0]["line"] is None
