"""Tests for the abstract base scanner class."""

import subprocess
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger

from devsecops_radar.scanners.base import BaseScanner, ScannerFinding


# ---------------------------------------------------------------------------
# Capture loguru output helper
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
# Concrete scanner for testing abstract methods
# ---------------------------------------------------------------------------
class _DummyScanner(BaseScanner):
    def _default_binary_name(self) -> str:
        return "dummy"

    def run(self, target: str) -> list[ScannerFinding]:
        self._validate_target_path(target)
        return [ScannerFinding(id="R1", tool="dummy", target=target, severity="LOW", title="Test")]

    def parse(self, file_path: str) -> list[ScannerFinding]:
        self._validate_target_path(file_path)
        return [ScannerFinding(id="R2", tool="dummy", target=file_path, severity="HIGH", title="Parsed")]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def safe_base(tmp_path):
    """Return a temporary base directory for path validation. Directory is created."""
    base = tmp_path / "safe"
    base.mkdir()
    return base


@pytest.fixture
def scanner(safe_base):
    """Create a DummyScanner with a safe base directory."""
    return _DummyScanner(allowed_base_dir=safe_base)


# ============================================================================
# Tests for __init__ and binary checks
# ============================================================================
class TestInit:
    def test_default_binary_name(self):
        s = _DummyScanner()
        assert s.binary_path == "dummy"

    def test_custom_binary_path(self):
        s = _DummyScanner(binary_path="custom-bin")
        assert s.binary_path == "custom-bin"

    def test_allowed_base_dir(self, tmp_path):
        s = _DummyScanner(allowed_base_dir=tmp_path)
        assert s.allowed_base_dir == tmp_path.resolve()

    def test_binary_missing_warning(self, safe_base):
        with patch("shutil.which", return_value=None):
            with capture_loguru() as msgs:
                _DummyScanner(allowed_base_dir=safe_base)
            assert any("not found in PATH" in m for m in msgs)

    def test_timeout_default(self):
        s = _DummyScanner()
        assert s.timeout == 300


# ============================================================================
# Tests for _validate_target_path
# ============================================================================
class TestValidateTargetPath:
    def test_safe_path(self, scanner, safe_base):
        f = safe_base / "file.txt"
        f.touch()
        result = scanner._validate_target_path(str(f))
        assert result == str(f)

    def test_path_traversal_blocked(self, scanner, safe_base, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.touch()
        with capture_loguru() as msgs:
            result = scanner._validate_target_path(str(outside))
        assert result is None
        assert any("outside the allowed directory" in m for m in msgs)

    def test_resolution_error(self, scanner, safe_base):
        with patch.object(Path, "resolve", side_effect=OSError("fail")):
            with capture_loguru() as msgs:
                result = scanner._validate_target_path("file.txt")
        assert result is None
        assert any("Path validation failed" in m for m in msgs)


# ============================================================================
# Tests for _safe_run_command
# ============================================================================
class TestSafeRunCommand:
    def test_success(self, scanner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            scanner._safe_run_command(["dummy", "scan", "."])
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert args[0] == ["dummy", "scan", "."]
        assert kwargs["timeout"] == 300
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True

    def test_timeout(self, scanner):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="dummy", timeout=300)):
            with capture_loguru() as msgs:
                with pytest.raises(subprocess.TimeoutExpired):
                    scanner._safe_run_command(["dummy"])
            assert any("timed out" in m for m in msgs)

    def test_file_not_found(self, scanner):
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            with capture_loguru() as msgs:
                with pytest.raises(FileNotFoundError):
                    scanner._safe_run_command(["dummy"])
            assert any("Executable not found" in m for m in msgs)

    def test_empty_args_raises(self, scanner):
        with pytest.raises(ValueError, match="cannot be empty"):
            scanner._safe_run_command([])


# ============================================================================
# Tests for concrete methods (coverage on _DummyScanner)
# ============================================================================
class TestConcreteMethods:
    def test_run(self, scanner, safe_base):
        target = safe_base / "target"
        target.touch()
        findings = scanner.run(str(target))
        assert len(findings) == 1
        assert findings[0]["id"] == "R1"

    def test_parse(self, scanner, safe_base):
        target = safe_base / "results.json"
        target.touch()
        findings = scanner.parse(str(target))
        assert len(findings) == 1
        assert findings[0]["id"] == "R2"
