# tests/test_adapter.py (mypy‑clean)
"""Comprehensive tests for the ScannerAdapter bridge.

Covers path‑confined parsing, direct execution, fallback behaviour when
run() returns None, file‑size limits, and error propagation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from devsecops_radar.scanners.adapter import ScannerAdapter


class FakeScanner:
    """A minimal scanner that records calls and returns synthetic data."""

    def __init__(self) -> None:
        self.parse_calls: list[str] = []
        self.run_calls: list[str] = []
        self._return_run: list[dict[str, Any]] | None = None
        self._return_parse: list[dict[str, Any]] = [
            {"tool": "fake", "target": "/app", "id": "F1", "severity": "LOW", "title": "T", "description": ""}
        ]
        self._validate_findings_called: bool = False
        self._validate_findings_ret: list[dict[str, Any]] = []
        # Simulate the optional attribute
        self._has_validate_findings: bool = False

    def parse(self, file_path: str) -> list[dict[str, Any]]:
        self.parse_calls.append(file_path)
        return self._return_parse

    def run(self, target: str) -> list[dict[str, Any]] | None:
        self.run_calls.append(target)
        return self._return_run

    @property
    def allowed_base_dir(self) -> Path:
        return Path.cwd()

    @allowed_base_dir.setter
    def allowed_base_dir(self, value: Path) -> None:
        pass  # just accept it

    def _validate_findings(self, raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self._validate_findings_called = True
        return self._validate_findings_ret or raw


@pytest.fixture
def base(tmp_path: Path) -> Path:
    d = tmp_path / "base"
    d.mkdir()
    return d


@pytest.fixture
def scanner() -> FakeScanner:
    return FakeScanner()


@pytest.fixture
def adapter(scanner: FakeScanner, base: Path) -> ScannerAdapter:
    return ScannerAdapter(scanner, base_dir=base)


class TestAdapterParse:
    def test_valid_file_inside_base(
        self, adapter: ScannerAdapter, scanner: FakeScanner, base: Path
    ) -> None:
        f = base / "report.json"
        f.write_text(json.dumps([{"id": "X", "severity": "HIGH"}]))
        scanner._return_parse = [
            {"tool": "fake", "target": str(f), "id": "X", "severity": "HIGH", "title": "T", "description": ""}
        ]
        findings = adapter.parse(str(f))
        assert len(findings) == 1
        assert findings[0].id == "X"

    def test_file_outside_base_returns_empty(
        self, adapter: ScannerAdapter, base: Path, tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside.json"
        outside.write_text("[]")
        findings = adapter.parse(str(outside))
        assert findings == []

    def test_missing_file_returns_empty(self, adapter: ScannerAdapter, base: Path) -> None:
        findings = adapter.parse(str(base / "ghost.json"))
        assert findings == []

    def test_file_too_large_is_skipped(
        self, adapter: ScannerAdapter, scanner: FakeScanner, base: Path
    ) -> None:
        big = base / "big.json"
        big.write_text("x" * 100)
        with patch("os.fstat") as mock_fstat:
            mock_fstat.return_value.st_size = 60 * 1024 * 1024
            findings = adapter.parse(str(big))
        assert findings == []

    def test_os_error_on_fstat_returns_empty(
        self, adapter: ScannerAdapter, base: Path
    ) -> None:
        f = base / "err.json"
        f.write_text("[]")
        with patch("os.fstat", side_effect=OSError("bad fd")):
            findings = adapter.parse(str(f))
        assert findings == []

    def test_scanner_parse_exception_is_swallowed(
        self, adapter: ScannerAdapter, scanner: FakeScanner, base: Path
    ) -> None:
        f = base / "crash.json"
        f.write_text("{}")
        original_parse = scanner.parse
        scanner.parse = MagicMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
        try:
            findings = adapter.parse(str(f))
            assert findings == []
        finally:
            scanner.parse = original_parse  # type: ignore[method-assign]

    def test_validate_findings_called_when_present(
        self, adapter: ScannerAdapter, scanner: FakeScanner, base: Path
    ) -> None:
        f = base / "v.json"
        f.write_text("[]")
        scanner._validate_findings_ret = [
            {"tool": "fake", "target": str(f), "id": "V", "severity": "MEDIUM", "title": "X", "description": ""}
        ]
        scanner._has_validate_findings = True
        findings = adapter.parse(str(f))
        assert scanner._validate_findings_called
        assert findings[0].id == "V"


class TestAdapterRun:
    def test_run_successful(
        self, adapter: ScannerAdapter, scanner: FakeScanner, base: Path
    ) -> None:
        target = base / "code"
        target.mkdir()
        scanner._return_run = [
            {"tool": "fake", "target": str(target), "id": "R1", "severity": "HIGH", "title": "X", "description": ""}
        ]
        findings = adapter.run(str(target))
        assert len(findings) == 1
        assert findings[0].id == "R1"

    def test_run_returns_none_falls_back_to_parse(
        self, adapter: ScannerAdapter, scanner: FakeScanner, base: Path
    ) -> None:
        f = base / "fallback.json"
        f.write_text("[]")
        scanner._return_run = None
        findings = adapter.run(str(f))
        assert len(findings) >= 1

    def test_run_returns_none_non_file_target_returns_empty(
        self, adapter: ScannerAdapter, scanner: FakeScanner
    ) -> None:
        scanner._return_run = None
        findings = adapter.run("some-image:latest")
        assert findings == []

    def test_run_outside_path_rejected(
        self, adapter: ScannerAdapter, base: Path, tmp_path: Path
    ) -> None:
        outside = tmp_path / "../secret"
        findings = adapter.run(str(outside))
        assert findings == []

    def test_run_empty_target_returns_empty(self, adapter: ScannerAdapter) -> None:
        findings = adapter.run("")
        assert findings == []

    def test_run_exception_is_caught(
        self, adapter: ScannerAdapter, scanner: FakeScanner, base: Path
    ) -> None:
        target = base / "boom"
        target.mkdir()
        original_run = scanner.run
        scanner.run = MagicMock(side_effect=RuntimeError("fail"))  # type: ignore[method-assign]
        try:
            findings = adapter.run(str(target))
            assert findings == []
        finally:
            scanner.run = original_run  # type: ignore[method-assign]
