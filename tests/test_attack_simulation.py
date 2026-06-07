import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

from devsecops_radar.core.attack_simulation import (
    _cleanup_temp_dir,
    _generate_dummy_script,
    _sanitize_for_bash,
    logger,
    run_sandboxed_poc,
    simulate_attack,
)


# -----------------------------------------------
# _sanitize_for_bash
# -----------------------------------------------
class TestSanitizeForBash:
    def test_no_special_chars(self):
        assert _sanitize_for_bash("hello world") == "hello world"

    def test_single_quotes_escaped(self):
        assert _sanitize_for_bash("it's") == "it'\\''s"

    def test_empty_string(self):
        assert _sanitize_for_bash("") == ""


# -----------------------------------------------
# _cleanup_temp_dir
# -----------------------------------------------
class TestCleanupTempDir:
    def test_success(self):
        with patch("shutil.rmtree") as mock_rmtree, \
             patch.object(logger, "debug") as mock_debug:
            _cleanup_temp_dir("/tmp/dir")
            mock_rmtree.assert_called_once_with("/tmp/dir")
            mock_debug.assert_called_once()

    def test_failure(self):
        with patch("shutil.rmtree", side_effect=OSError("permission")), \
             patch.object(logger, "error") as mock_error:
            _cleanup_temp_dir("/tmp/dir")
            mock_error.assert_called_once()
            assert "Failed to clean up temp directory" in mock_error.call_args[0][0]


# -----------------------------------------------
# simulate_attack
# -----------------------------------------------
class TestSimulateAttack:
    def test_valid_finding(self):
        finding = {"id": "RCE-001", "title": "Remote Code Execution"}
        mock_dir = os.path.join(tempfile.gettempdir(), "sim_123")
        expected_path = os.path.join(mock_dir, "poc.sh")
        with patch("tempfile.mkdtemp", return_value=mock_dir), \
             patch("builtins.open", mock_open()) as mock_file, \
             patch("os.chmod") as mock_chmod, \
             patch.object(logger, "debug") as mock_debug:
            path = simulate_attack(finding)
            assert path == expected_path
            mock_file.assert_called_once_with(expected_path, "w")
            handle = mock_file()
            written = handle.write.call_args[0][0]
            assert "#!/bin/bash" in written
            assert "RCE-001" in written
            assert "Remote Code Execution" in written
            mock_chmod.assert_called_once_with(expected_path, 0o500)
            mock_debug.assert_called_once()

    def test_invalid_finding_not_dict(self):
        with patch("devsecops_radar.core.attack_simulation._generate_dummy_script",
                   return_value="/dummy/path/poc.sh") as mock_dummy, \
             patch.object(logger, "error") as mock_error:
            path = simulate_attack(["list"])
            assert path == "/dummy/path/poc.sh"
            mock_error.assert_called_once_with("Invalid finding data for attack simulation.")
            mock_dummy.assert_called_once_with("Invalid finding data provided.")

    def test_missing_id(self):
        finding = {"title": "No ID"}
        with patch("devsecops_radar.core.attack_simulation._generate_dummy_script",
                   return_value="/dummy/path/poc.sh") as mock_dummy, \
             patch.object(logger, "error") as mock_error:
            path = simulate_attack(finding)
            assert path == "/dummy/path/poc.sh"
            mock_error.assert_called_once_with("Invalid finding data for attack simulation.")
            mock_dummy.assert_called_once_with("Invalid finding data provided.")

    def test_missing_title(self):
        finding = {"id": "R1"}
        with patch("devsecops_radar.core.attack_simulation._generate_dummy_script",
                   return_value="/dummy/path/poc.sh") as mock_dummy, \
             patch.object(logger, "error") as mock_error:
            path = simulate_attack(finding)
            assert path == "/dummy/path/poc.sh"
            mock_error.assert_called_once_with("Invalid finding data for attack simulation.")
            mock_dummy.assert_called_once_with("Invalid finding data provided.")

    def test_script_write_failure(self):
        finding = {"id": "XSS", "title": "XSS Vuln"}
        mock_dir = os.path.join(tempfile.gettempdir(), "sim_fail")
        with patch("tempfile.mkdtemp", return_value=mock_dir), \
             patch("builtins.open", side_effect=OSError("disk full")), \
             patch("devsecops_radar.core.attack_simulation._generate_dummy_script",
                   return_value="/dummy/path/poc.sh") as mock_dummy, \
             patch.object(logger, "error") as mock_error:
            path = simulate_attack(finding)
            assert path == "/dummy/path/poc.sh"
            mock_error.assert_called_once()
            assert "Failed to write simulation script" in mock_error.call_args[0][0]
            mock_dummy.assert_called_once_with("Script creation failed.")


# -----------------------------------------------
# _generate_dummy_script
# -----------------------------------------------
class TestGenerateDummyScript:
    def test_generates_script(self):
        dummy_dir = os.path.join(tempfile.gettempdir(), "dummy_123")
        expected_path = os.path.join(dummy_dir, "poc.sh")
        with patch("tempfile.mkdtemp", return_value=dummy_dir), \
             patch("builtins.open", mock_open()) as mock_file, \
             patch("os.chmod") as mock_chmod:
            path = _generate_dummy_script("Some reason")
            assert path == expected_path
            handle = mock_file()
            written = handle.write.call_args[0][0]
            assert "#!/bin/bash" in written
            assert "Simulation skipped: Some reason" in written
            mock_chmod.assert_called_once_with(expected_path, 0o500)


# -----------------------------------------------
# run_sandboxed_poc
# -----------------------------------------------
class TestRunSandboxedPoc:
    def test_script_path_none(self):
        with patch.object(logger, "error") as mock_error:
            result = run_sandboxed_poc(None)
            assert "no script path" in result
            mock_error.assert_called_once()

    def test_script_not_found(self):
        with patch.object(Path, "is_file", return_value=False), \
             patch.object(logger, "error") as mock_error:
            result = run_sandboxed_poc("/nonexistent/poc.sh")
            assert "script file not found" in result
            mock_error.assert_called_once()

    def test_script_outside_temp_dir(self):
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "is_relative_to", return_value=False), \
             patch.object(logger, "error") as mock_error:
            result = run_sandboxed_poc("/etc/passwd")
            assert "script location is not allowed" in result
            mock_error.assert_called_once()

    def test_script_path_contains_colon(self):
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "resolve", return_value=Path("/tmp/safe:poc.sh")), \
             patch("tempfile.gettempdir", return_value="/tmp"), \
             patch.object(logger, "error") as mock_error:
            result = run_sandboxed_poc("/tmp/safe:poc.sh")
            assert "invalid characters in script path" in result
            mock_error.assert_called_once()

    def test_docker_not_found(self):
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "resolve", return_value=Path("/tmp/safe.sh")), \
             patch("tempfile.gettempdir", return_value="/tmp"), \
             patch.object(Path, "is_relative_to", return_value=True), \
             patch("shutil.which", return_value=None), \
             patch.object(logger, "warning") as mock_warning:
            result = run_sandboxed_poc("/tmp/safe.sh")
            assert "Docker is not installed" in result
            mock_warning.assert_called_once()

    def test_docker_success(self):
        script = "/tmp/poc.sh"
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "resolve", return_value=Path(script)), \
             patch("tempfile.gettempdir", return_value="/tmp"), \
             patch.object(Path, "is_relative_to", return_value=True), \
             patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("subprocess.run") as mock_run, \
             patch("devsecops_radar.core.attack_simulation._cleanup_temp_dir") as mock_cleanup, \
             patch.object(logger, "info"), \
             patch.object(logger, "success") as mock_success:
            mock_run.return_value = MagicMock(returncode=0, stdout="success\n", stderr="")
            result = run_sandboxed_poc(script)
            assert result == "success"
            mock_cleanup.assert_called_once_with(Path(script).parent)
            mock_success.assert_called_once()

    def test_docker_nonzero_exit(self):
        script = "/tmp/poc.sh"
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "resolve", return_value=Path(script)), \
             patch("tempfile.gettempdir", return_value="/tmp"), \
             patch.object(Path, "is_relative_to", return_value=True), \
             patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("subprocess.run") as mock_run, \
             patch.object(logger, "warning") as mock_warning:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            result = run_sandboxed_poc(script)
            assert "Sandbox execution failed (exit 1)" in result
            assert "error" in result
            mock_warning.assert_called_once()

    def test_docker_timeout(self):
        script = "/tmp/poc.sh"
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "resolve", return_value=Path(script)), \
             patch("tempfile.gettempdir", return_value="/tmp"), \
             patch.object(Path, "is_relative_to", return_value=True), \
             patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 30)), \
             patch.object(logger, "error") as mock_error:
            result = run_sandboxed_poc(script)
            assert "timed out" in result
            mock_error.assert_called_once()

    def test_docker_unexpected_exception(self):
        script = "/tmp/poc.sh"
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "resolve", return_value=Path(script)), \
             patch("tempfile.gettempdir", return_value="/tmp"), \
             patch.object(Path, "is_relative_to", return_value=True), \
             patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("subprocess.run", side_effect=Exception("unknown")), \
             patch.object(logger, "error") as mock_error:
            result = run_sandboxed_poc(script)
            assert "Sandbox execution failed" in result
            mock_error.assert_called_once()
