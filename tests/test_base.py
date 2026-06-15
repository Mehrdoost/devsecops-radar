"""Tests for the abstract base scanner class – updated."""

import subprocess
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger

from devsecops_radar.scanners.base import BaseScanner, ScannerFinding


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


class _DummyScanner(BaseScanner):
    def _default_binary_name(self) -> str:
        return "dummy"
    def run(self, target: str) -> list[ScannerFinding]:
        self._validate_target_path(target)
        return [ScannerFinding(id="R1", tool="dummy", target=target, severity="LOW", title="T")]
    def parse(self, file_path: str) -> list[ScannerFinding]:
        self._validate_target_path(file_path)
        return [ScannerFinding(id="R2", tool="dummy", target=file_path, severity="HIGH", title="T")]


@pytest.fixture
def safe_base(tmp_path):
    base = tmp_path / "safe"
    base.mkdir()
    return base


@pytest.fixture
def scanner(safe_base):
    return _DummyScanner(allowed_base_dir=safe_base)


class TestInit:
    def test_default_binary(self):
        assert _DummyScanner().binary_path == "dummy"
    def test_allowed_base(self, tmp_path):
        s = _DummyScanner(allowed_base_dir=tmp_path)
        assert s.allowed_base_dir == tmp_path.resolve()


class TestValidateTargetPath:
    def test_safe(self, scanner, safe_base):
        f = safe_base / "file.txt"
        f.touch()
        assert scanner._validate_target_path(str(f)) == str(f)

    def test_traversal(self, scanner, safe_base, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.touch()
        with capture_loguru() as msgs:
            assert scanner._validate_target_path(str(outside)) is None
        assert any("outside the allowed directory" in m for m in msgs)


class TestSafeRunCommand:
    def test_success(self, scanner):
        with patch("subprocess.run") as mock_run, \
             patch("shutil.which", return_value="/fake/path/dummy"):
            mock_run.return_value = MagicMock(returncode=0)
            scanner._safe_run_command(["dummy", "scan", "."])
        mock_run.assert_called_once_with(
            ["/fake/path/dummy", "scan", "."],
            capture_output=True, text=True, timeout=300, check=False,
        )

    def test_timeout(self, scanner):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="d", timeout=300)), \
             patch("shutil.which", return_value="/fake/path/dummy"):
            with pytest.raises(subprocess.TimeoutExpired):
                scanner._safe_run_command(["dummy"])

    def test_binary_not_found(self, scanner):
        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError, match="Required executable not found"):
                scanner._safe_run_command(["dummy"])


class TestConcreteMethods:
    def test_run(self, scanner, safe_base):
        target = safe_base / "t"
        target.touch()
        assert len(scanner.run(str(target))) == 1
    def test_parse(self, scanner, safe_base):
        f = safe_base / "r.json"
        f.touch()
        assert len(scanner.parse(str(f))) == 1
