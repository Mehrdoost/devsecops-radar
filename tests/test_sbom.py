import json
import subprocess
from unittest.mock import mock_open, patch

import pytest

from devsecops_radar.core.sbom import (
    _is_safe_path,
    apply_vex_filter,
    detect_dependency_confusion,
    generate_sbom,
    logger,
)


# -----------------------------------------------
# Tests for _is_safe_path
# -----------------------------------------------
class TestIsSafePath:
    def test_safe_relative_path(self):
        assert _is_safe_path("src") is True

    def test_safe_subdir_path(self):
        assert _is_safe_path("sub/dir/file.txt") is True

    def test_unsafe_parent_traversal(self):
        # "../" should be blocked (no exception → no log)
        result = _is_safe_path("../etc/passwd")
        assert result is False

    def test_unsafe_absolute_outside_cwd(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        result = _is_safe_path(str(tmp_path / "unsafe"), base_dir=base)
        assert result is False

    def test_resolution_error(self):
        with patch("pathlib.Path.resolve", side_effect=OSError("mock error")), \
             patch.object(logger, "error") as mock_log:
            result = _is_safe_path("anything")
            assert result is False
            mock_log.assert_called_once()
            assert "Path resolution error" in mock_log.call_args[0][0]


# -----------------------------------------------
# Tests for generate_sbom
# -----------------------------------------------
class TestGenerateSbom:
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        self.mock_which = patch("devsecops_radar.core.sbom.shutil.which", return_value="/usr/bin/syft")
        self.mock_run = patch("devsecops_radar.core.sbom.subprocess.run")
        self.mock_exists = patch("devsecops_radar.core.sbom.Path.exists", return_value=True)
        self.mock_open = patch("builtins.open", mock_open(read_data='{"sbom": "test"}'))
        self.mock_is_safe = patch("devsecops_radar.core.sbom._is_safe_path", return_value=True)

        self.mock_which.start()
        self.mock_run.start()
        self.mock_exists.start()
        self.mock_open.start()
        self.mock_is_safe.start()

        yield

        self.mock_which.stop()
        self.mock_run.stop()
        self.mock_exists.stop()
        self.mock_open.stop()
        self.mock_is_safe.stop()

    def test_successful_generation(self):
        result = generate_sbom("src", "sbom.json")
        assert result == {"sbom": "test"}
        subprocess.run.assert_called_once_with(
            ["syft", "scan", "src", "-o", "cyclonedx-json", "--output", "sbom.json"],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_path_validation_fails(self):
        with patch("devsecops_radar.core.sbom._is_safe_path", return_value=False), \
             patch.object(logger, "error") as mock_log:
            result = generate_sbom("unsafe_dir")
            assert result is None
            mock_log.assert_called_with(
                "SBOM generation blocked: target directory or output file is outside allowed path."
            )

    def test_syft_not_installed(self):
        with patch("devsecops_radar.core.sbom.shutil.which", return_value=None), \
             patch.object(logger, "error") as mock_log:
            result = generate_sbom("src")
            assert result is None
            mock_log.assert_called_with("syft is not installed. Cannot generate SBOM.")

    def test_subprocess_called_process_error(self):
        with patch("devsecops_radar.core.sbom.subprocess.run") as mock_run, \
             patch.object(logger, "error") as mock_log:
            mock_run.side_effect = subprocess.CalledProcessError(1, "syft", stderr="some error")
            result = generate_sbom("src")
            assert result is None
            mock_log.assert_called_with("syft failed: some error")

    def test_subprocess_timeout(self):
        with patch("devsecops_radar.core.sbom.subprocess.run") as mock_run, \
             patch.object(logger, "error") as mock_log:
            mock_run.side_effect = subprocess.TimeoutExpired("syft", 120)
            result = generate_sbom("src")
            assert result is None
            mock_log.assert_called_with("syft timed out.")

    def test_output_file_not_created(self):
        with patch("devsecops_radar.core.sbom.Path.exists", return_value=False), \
             patch.object(logger, "error") as mock_log:
            result = generate_sbom("src", "out.json")
            assert result is None
            mock_log.assert_called_with("SBOM file was not created: out.json")

    def test_generic_exception(self):
        with patch("devsecops_radar.core.sbom.subprocess.run") as mock_run, \
             patch.object(logger, "error") as mock_log:
            mock_run.side_effect = RuntimeError("disk full")
            result = generate_sbom("src")
            assert result is None
            mock_log.assert_called_with("SBOM generation failed: disk full")


# -----------------------------------------------
# Tests for detect_dependency_confusion
# -----------------------------------------------
class TestDetectDependencyConfusion:
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        self._safe_patch = patch("devsecops_radar.core.sbom._is_safe_path", return_value=True)
        self._safe_patch.start()
        # By default make Path.is_file return True (tests that need False will override)
        self._isfile_patch = patch("devsecops_radar.core.sbom.Path.is_file", return_value=True)
        self._isfile_patch.start()
        yield
        self._safe_patch.stop()
        self._isfile_patch.stop()

    def test_safe_path_blocked(self):
        with patch("devsecops_radar.core.sbom._is_safe_path", return_value=False), \
             patch.object(logger, "error") as mock_log:
            findings = detect_dependency_confusion("bad.json")
            assert findings == []
            mock_log.assert_called_with("Blocked reading manifest: bad.json is outside allowed path.")

    def test_file_not_found(self):
        # Override is_file to False for this test
        with patch("devsecops_radar.core.sbom.Path.is_file", return_value=False), \
             patch.object(logger, "warning") as mock_log:
            findings = detect_dependency_confusion("missing.json")
            assert findings == []
            mock_log.assert_called_with("Manifest file not found: missing.json")

    def test_package_json_valid(self):
        manifest_data = json.dumps({
            "dependencies": {
                "mycompany-lib": "1.0.0",
                "public-dep": "2.0.0"
            },
            "devDependencies": {
                "internal-utils": "0.5.0"
            }
        })
        with patch("builtins.open", mock_open(read_data=manifest_data)):
            findings = detect_dependency_confusion("package.json")
            assert len(findings) == 2
            assert findings[0]["package"] == "mycompany-lib"
            assert findings[1]["package"] == "internal-utils"

    def test_package_json_no_matches(self):
        manifest_data = json.dumps({"dependencies": {"public-lib": "1.0.0"}})
        with patch("builtins.open", mock_open(read_data=manifest_data)):
            findings = detect_dependency_confusion("package.json", internal_prefixes=["internal-"])
            assert findings == []

    def test_requirements_txt_valid(self):
        content = "mycompany-core==1.0.0\npublic-lib>=2.0\n# comment\n\ninternal-pkg ~=0.1"
        with patch("builtins.open", mock_open(read_data=content)):
            findings = detect_dependency_confusion(
                "requirements.txt", internal_prefixes=["mycompany-", "internal-"]
            )
            assert len(findings) == 2
            assert findings[0]["package"] == "mycompany-core"
            assert findings[1]["package"] == "internal-pkg"

    def test_unsupported_format(self):
        with patch("builtins.open", mock_open(read_data="some content")), \
             patch.object(logger, "info") as mock_log:
            findings = detect_dependency_confusion("Pipfile")
            assert findings == []
            mock_log.assert_called_with("Unsupported manifest format: Pipfile")

    def test_json_decode_error(self):
        with patch("builtins.open", mock_open(read_data="{invalid json")), \
             patch.object(logger, "error") as mock_log:
            findings = detect_dependency_confusion("package.json")
            assert findings == []
            mock_log.assert_called_with("Invalid JSON in package.json")

    def test_generic_exception(self):
        with patch("builtins.open", side_effect=PermissionError("access denied")), \
             patch.object(logger, "error") as mock_log:
            findings = detect_dependency_confusion("requirements.txt")
            assert findings == []
            mock_log.assert_called_with("Error scanning manifest requirements.txt: access denied")


# -----------------------------------------------
# Tests for apply_vex_filter
# -----------------------------------------------
class TestApplyVexFilter:
    def test_vex_file_does_not_exist(self):
        findings = [{"id": "CVE-001", "status": "open"}]
        result = apply_vex_filter(findings, "nonexistent.json")
        assert result == findings

    def test_vex_path_not_safe(self):
        with patch("devsecops_radar.core.sbom._is_safe_path", return_value=False), \
             patch("os.path.exists", return_value=True), \
             patch.object(logger, "error") as mock_log:
            findings = [{"id": "CVE-001"}]
            result = apply_vex_filter(findings, "unsafe.json")
            assert result == findings
            mock_log.assert_called_with("VEX file path is not allowed: unsafe.json")

    def test_vex_json_invalid(self):
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", side_effect=json.JSONDecodeError("msg", "", 0)), \
             patch.object(logger, "error") as mock_log:
            findings = [{"id": "CVE-001"}]
            result = apply_vex_filter(findings, "vex.json")
            assert result == findings
            mock_log.assert_called()

    def test_filtering_not_affected_and_false_positive(self):
        vex_data = {
            "vulnerabilities": [
                {"id": "CVE-001", "analysis": {"state": "not_affected"}},
                {"id": "CVE-002", "analysis": {"state": "false_positive"}},
                {"id": "CVE-003", "analysis": {"state": "under_investigation"}},
            ]
        }
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=json.dumps(vex_data))), \
             patch.object(logger, "info") as mock_log:
            findings = [
                {"id": "CVE-001", "severity": "high"},
                {"id": "CVE-002", "severity": "medium"},
                {"id": "CVE-003", "severity": "low"},
                {"id": "CVE-004", "severity": "critical"},
            ]
            result = apply_vex_filter(findings, "vex.json")
            assert len(result) == 2
            assert result[0]["id"] == "CVE-003"
            assert result[1]["id"] == "CVE-004"
            mock_log.assert_called_with("VEX filter applied: 2 findings excluded.")

    def test_no_vulnerabilities_in_vex(self):
        vex_data = {"vulnerabilities": []}
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=json.dumps(vex_data))):
            findings = [{"id": "CVE-001"}]
            result = apply_vex_filter(findings, "vex.json")
            assert result == findings

    def test_empty_findings(self):
        vex_data = {"vulnerabilities": [{"id": "CVE-001", "analysis": {"state": "not_affected"}}]}
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=json.dumps(vex_data))):
            result = apply_vex_filter([], "vex.json")
            assert result == []
