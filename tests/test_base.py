import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from devsecops_radar.scanners.base import BaseScanner, ScannerFinding, logger


# ---------------------------------------------------------------------------
# Concrete subclass for testing abstract methods
# ---------------------------------------------------------------------------
class _TestScanner(BaseScanner):
    name = "test"

    def _default_binary_name(self) -> str:
        return "test_binary"

    def run(self, target: str) -> list[ScannerFinding]:
        safe = self._validate_target_path(target)
        if not safe:
            return []
        return [{"tool": "test", "target": safe, "id": "1", "severity": "HIGH", "title": "found"}]

    def parse(self, file_path: str) -> list[ScannerFinding]:
        return [{"tool": "test", "target": file_path, "id": "2", "severity": "LOW", "title": "parsed"}]


# ---------------------------------------------------------------------------
# Tests for _validate_target_path
# ---------------------------------------------------------------------------
class TestValidateTargetPath:
    @pytest.fixture
    def scanner(self, tmp_path):
        # Create a scanner with allowed_base_dir set to tmp_path
        return _TestScanner(allowed_base_dir=tmp_path)

    def test_path_inside_allowed(self, scanner, tmp_path):
        target = tmp_path / "sub" / "file.txt"
        target.parent.mkdir()
        target.touch()
        result = scanner._validate_target_path(str(target))
        assert result == str(target.resolve())

    def test_path_outside_allowed(self, scanner, tmp_path):
        # target is outside tmp_path
        outside = tmp_path.parent / "outside.txt"
        outside.touch()
        with patch.object(logger, "error") as mock_log:
            result = scanner._validate_target_path(str(outside))
            assert result is None
            mock_log.assert_called_once()
            assert "Security Violation" in mock_log.call_args[0][0]

    def test_path_does_not_exist_but_inside(self, scanner, tmp_path):
        # Resolution does not require existence, so it should be allowed
        target = tmp_path / "nonexistent.txt"
        result = scanner._validate_target_path(str(target))
        assert result == str(target.resolve())

    def test_exception_during_resolution(self, scanner):
        with patch.object(Path, "resolve", side_effect=Exception("disk error")), \
             patch.object(logger, "error") as mock_log:
            result = scanner._validate_target_path("anything")
            assert result is None
            mock_log.assert_called_once()
            assert "Path validation failed" in mock_log.call_args[0][0]


# ---------------------------------------------------------------------------
# Tests for _safe_run_command
# ---------------------------------------------------------------------------
class TestSafeRunCommand:
    @pytest.fixture
    def scanner(self, tmp_path):
        return _TestScanner(allowed_base_dir=tmp_path, timeout=5)

    def test_success(self, scanner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=["echo"], returncode=0, stdout="ok", stderr="")
            result = scanner._safe_run_command(["echo", "hello"])
            assert result.returncode == 0
            mock_run.assert_called_once_with(
                ["echo", "hello"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )

    def test_timeout(self, scanner):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5)), \
             patch.object(logger, "error") as mock_log:
            with pytest.raises(subprocess.TimeoutExpired):
                scanner._safe_run_command(["cmd"])
            mock_log.assert_called_once()
            assert "timed out" in mock_log.call_args[0][0]

    def test_file_not_found(self, scanner):
        with patch("subprocess.run", side_effect=FileNotFoundError), \
             patch.object(logger, "error") as mock_log:
            with pytest.raises(FileNotFoundError):
                scanner._safe_run_command(["nonexistent_binary"])
            mock_log.assert_called_once()
            assert "not found in PATH" in mock_log.call_args[0][0]

    def test_empty_command_raises_value_error(self, scanner):
        with pytest.raises(ValueError, match="cannot be empty"):
            scanner._safe_run_command([])

    def test_logs_command(self, scanner):
        with patch("subprocess.run"):
            with patch.object(logger, "debug") as mock_debug:
                scanner._safe_run_command(["ls", "-la"])
                mock_debug.assert_called_once()
                assert "ls -la" in mock_debug.call_args[0][0]


# ---------------------------------------------------------------------------
# Tests for constructor and default binary
# ---------------------------------------------------------------------------
class TestBaseScannerInit:
    def test_defaults(self, tmp_path):
        scanner = _TestScanner()
        assert scanner.timeout == 300
        assert scanner.binary_path == "test_binary"
        assert scanner.allowed_base_dir == Path.cwd()

    def test_custom_timeout_and_binary(self, tmp_path):
        scanner = _TestScanner(timeout=60, binary_path="/custom/binary")
        assert scanner.timeout == 60
        assert scanner.binary_path == "/custom/binary"

    def test_custom_allowed_dir(self, tmp_path):
        scanner = _TestScanner(allowed_base_dir=tmp_path)
        assert scanner.allowed_base_dir == tmp_path.resolve()

    def test_default_binary_name(self):
        scanner = _TestScanner()
        assert scanner._default_binary_name() == "test_binary"
