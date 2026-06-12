"""Tests for attack simulation module (updated)."""

import os
import subprocess
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from loguru import logger

from devsecops_radar.core.attack_simulation import (
    _MAX_FIELD_LENGTH,
    _cleanup_temp_dir,
    _generate_dummy_script,
    _is_docker_available,
    _sanitize_for_bash,
    run_sandboxed_poc,
    simulate_attack,
)


# ---------------------------------------------------------------------------
# Helper to capture loguru output
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
# Tests for _sanitize_for_bash
# ---------------------------------------------------------------------------
class TestSanitizeForBash:
    def test_alphanumeric_and_allowed_special(self):
        assert _sanitize_for_bash("hello-world_123.4/5 6") == "hello-world_123.4/5 6"

    def test_removes_unsafe_characters(self):
        assert _sanitize_for_bash("a$b!c@d;e'f") == "abcdef"

    def test_empty_string_returns_empty(self):
        assert _sanitize_for_bash("") == ""

    def test_non_string_input_returns_empty(self):
        assert _sanitize_for_bash(123) == ""

    def test_newlines_and_carriage_returns_removed(self):
        assert _sanitize_for_bash("line1\nline2\rline3") == "line1line2line3"

    def test_stripping_leading_trailing_spaces(self):
        assert _sanitize_for_bash("  hello  ") == "hello"


# ---------------------------------------------------------------------------
# Tests for _cleanup_temp_dir
# ---------------------------------------------------------------------------
class TestCleanupTempDir:
    def test_success(self, tmp_path):
        d = tmp_path / "sub"
        d.mkdir()
        with capture_loguru() as msgs:
            _cleanup_temp_dir(str(d))
        assert not d.exists()
        assert any("Temporary directory removed" in m for m in msgs)

    def test_exception(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("data")
        with capture_loguru() as msgs:
            _cleanup_temp_dir(str(f))
        assert any("Failed to clean up temp directory" in m for m in msgs)


# ---------------------------------------------------------------------------
# Tests for _is_docker_available
# ---------------------------------------------------------------------------
class TestIsDockerAvailable:
    def test_no_cli(self):
        with patch("shutil.which", return_value=None):
            assert _is_docker_available() is False

    def test_cli_exists_daemon_ok(self):
        with patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            assert _is_docker_available() is True

    def test_cli_exists_daemon_unreachable(self):
        with patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=3)):
            assert _is_docker_available() is False


# ---------------------------------------------------------------------------
# Tests for _generate_dummy_script
# ---------------------------------------------------------------------------
class TestGenerateDummyScript:
    def test_creates_dummy_script(self):
        script_path = _generate_dummy_script("test reason")
        assert os.path.isfile(script_path)
        content = Path(script_path).read_text()
        assert "Simulation skipped: test reason" in content
        _cleanup_temp_dir(os.path.dirname(script_path))

    def test_sanitizes_reason(self):
        script_path = _generate_dummy_script("unsafe$!reason;")
        content = Path(script_path).read_text()
        assert "unsafereason" in content
        _cleanup_temp_dir(os.path.dirname(script_path))

    def test_truncates_long_reason(self):
        long_reason = "x" * 300
        script_path = _generate_dummy_script(long_reason)
        content = Path(script_path).read_text()
        truncated = "x" * _MAX_FIELD_LENGTH
        assert truncated in content
        _cleanup_temp_dir(os.path.dirname(script_path))


# ---------------------------------------------------------------------------
# Tests for simulate_attack
# ---------------------------------------------------------------------------
class TestSimulateAttack:
    def test_invalid_finding_none(self):
        with capture_loguru() as msgs:
            result_path = simulate_attack(None)
        content = Path(result_path).read_text()
        assert "Simulation skipped" in content
        assert any("Invalid finding data" in m for m in msgs)
        _cleanup_temp_dir(os.path.dirname(result_path))

    def test_invalid_finding_missing_id(self):
        finding = {"title": "No ID"}
        with capture_loguru() as msgs:
            result_path = simulate_attack(finding)
        content = Path(result_path).read_text()
        assert "Simulation skipped" in content
        assert any("Invalid finding data" in m for m in msgs)
        _cleanup_temp_dir(os.path.dirname(result_path))

    def test_invalid_finding_missing_title(self):
        finding = {"id": "F1"}
        with capture_loguru() as msgs:
            result_path = simulate_attack(finding)
        content = Path(result_path).read_text()
        assert "Simulation skipped" in content
        assert any("Invalid finding data" in m for m in msgs)
        _cleanup_temp_dir(os.path.dirname(result_path))

    def test_valid_finding(self):
        finding = {"id": "VULN-123", "title": "Remote Code Execution"}
        result_path = simulate_attack(finding)
        content = Path(result_path).read_text()
        assert "VULN-123" in content
        assert "Remote Code Execution" in content
        assert content.startswith("#!/bin/bash")
        _cleanup_temp_dir(os.path.dirname(result_path))

    def test_sanitization_of_id_and_title(self):
        finding = {"id": "bad$id;", "title": "cmd'injection\n"}
        result_path = simulate_attack(finding)
        content = Path(result_path).read_text()
        assert "badid" in content
        assert "cmd'injection" not in content
        assert "cmdinjection" in content
        _cleanup_temp_dir(os.path.dirname(result_path))

    def test_truncation_long_id_and_title(self):
        long_id = "A" * 300
        long_title = "B" * 300
        finding = {"id": long_id, "title": long_title}
        result_path = simulate_attack(finding)
        content = Path(result_path).read_text()
        assert "A" * _MAX_FIELD_LENGTH in content
        assert "B" * _MAX_FIELD_LENGTH in content
        assert "A" * (_MAX_FIELD_LENGTH + 1) not in content
        _cleanup_temp_dir(os.path.dirname(result_path))

    def test_script_creation_failure(self):
        finding = {"id": "F1", "title": "Issue"}
        with patch(
            "tempfile.mkdtemp",
            side_effect=[OSError("No space left"), "/fake/dummy_dir"],
        ):
            with patch(
                "devsecops_radar.core.attack_simulation._generate_dummy_script",
                return_value="/dummy/poc.sh",
            ) as mock_dummy:
                result = simulate_attack(finding)
        mock_dummy.assert_called_once_with("Script creation failed.")
        assert result == "/dummy/poc.sh"


# ---------------------------------------------------------------------------
# Tests for run_sandboxed_poc
# ---------------------------------------------------------------------------
class TestRunSandboxedPoc:
    def test_empty_path(self):
        with capture_loguru() as msgs:
            output = run_sandboxed_poc("")
        assert "no script path" in output.lower()
        assert any("No script path" in m for m in msgs)

    def test_nonexistent_file(self, tmp_path):
        path = str(tmp_path / "nonexistent.sh")
        with capture_loguru() as msgs:
            output = run_sandboxed_poc(path)
        assert "script file not found" in output.lower()
        assert any("does not exist" in m for m in msgs)

    def test_file_outside_tempdir(self, tmp_path):
        script = tmp_path / "poc.sh"
        script.write_text("#!/bin/bash\necho safe")
        script.chmod(0o755)
        other = tmp_path / "other"
        other.mkdir()
        with patch("tempfile.gettempdir", return_value=str(other)):
            with capture_loguru() as msgs:
                output = run_sandboxed_poc(str(script))
        assert "script location is not allowed" in output.lower()
        assert any("not inside the expected temp directory" in m for m in msgs)

    def test_toctou_symlink_detection(self, tmp_path):
        script = tmp_path / "poc.sh"
        script.write_text("#!/bin/bash\necho ok")
        with patch.object(Path, "is_file", return_value=True):
            with patch.object(Path, "is_relative_to", return_value=True):
                with patch("os.path.realpath", return_value="/etc/malicious"):
                    with patch("os.path.commonpath", return_value="different"):
                        output = run_sandboxed_poc(str(script))
        assert "script path tampering detected" in output.lower()

    def test_docker_daemon_unavailable(self, tmp_path):
        script = tmp_path / "test.sh"
        script.write_text("#!/bin/bash\necho safe")
        script.chmod(0o755)
        with patch("tempfile.gettempdir", return_value=str(tmp_path)):
            with patch("devsecops_radar.core.attack_simulation._is_docker_available", return_value=False):
                output = run_sandboxed_poc(str(script))
        assert "Docker daemon is not running" in output

    @patch("subprocess.run")
    def test_successful_run(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="OK output\n", stderr="")
        script = tmp_path / "poc.sh"
        script.write_text("#!/bin/bash\necho hi")
        script.chmod(0o755)
        with patch("tempfile.gettempdir", return_value=str(tmp_path)):
            with patch("devsecops_radar.core.attack_simulation._is_docker_available", return_value=True):
                with patch(
                    "devsecops_radar.core.attack_simulation._cleanup_temp_dir"
                ) as mock_cleanup:
                    output = run_sandboxed_poc(str(script))
        assert output == "OK output"
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert any(str(script) in a for a in args)
        mock_cleanup.assert_called_once_with(str(script.parent))

    @patch("subprocess.run")
    def test_docker_run_timeout(self, mock_run, tmp_path):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=30)
        script = tmp_path / "poc.sh"
        script.write_text("#!/bin/bash\nsleep 100")
        script.chmod(0o755)
        with patch("tempfile.gettempdir", return_value=str(tmp_path)):
            with patch("devsecops_radar.core.attack_simulation._is_docker_available", return_value=True):
                output = run_sandboxed_poc(str(script))
        assert "timed out" in output.lower()

    @patch("subprocess.run")
    def test_docker_run_nonzero_exit(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error details")
        script = tmp_path / "poc.sh"
        script.write_text("#!/bin/bash\nexit 1")
        script.chmod(0o755)
        with patch("tempfile.gettempdir", return_value=str(tmp_path)):
            with patch("devsecops_radar.core.attack_simulation._is_docker_available", return_value=True):
                with capture_loguru() as msgs:
                    output = run_sandboxed_poc(str(script))
        assert "failed (exit 1)" in output
        assert "error details" in output
        assert any("exited with code" in m for m in msgs)

    @patch("subprocess.run")
    def test_docker_not_installed_during_run(self, mock_run, tmp_path):
        script = tmp_path / "poc.sh"
        script.write_text("#!/bin/bash\necho")
        script.chmod(0o755)
        with patch("tempfile.gettempdir", return_value=str(tmp_path)):
            with patch("devsecops_radar.core.attack_simulation._is_docker_available", return_value=True):
                mock_run.side_effect = FileNotFoundError
                output = run_sandboxed_poc(str(script))
        assert "Docker is not installed or not running" in output

    @patch("subprocess.run")
    def test_unexpected_error(self, mock_run, tmp_path):
        mock_run.side_effect = Exception("Unknown error")
        script = tmp_path / "poc.sh"
        script.write_text("#!/bin/bash\necho")
        script.chmod(0o755)
        with patch("tempfile.gettempdir", return_value=str(tmp_path)):
            with patch("devsecops_radar.core.attack_simulation._is_docker_available", return_value=True):
                output = run_sandboxed_poc(str(script))
        assert "Sandbox execution failed" in output
        assert "Unknown error" in output
