# tests/test_scanners.py (mypy‑clean)
"""Comprehensive tests for all built‑in security scanners.

Covers parsing of pre‑existing reports, direct execution with mocked
subprocess, path confinement, error handling, and scanner‑specific
behaviours (e.g. Trivy image rejection, Zizmor missing location).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from devsecops_radar.scanners.gitleaks import GitleaksScanner
from devsecops_radar.scanners.poutine import PoutineScanner
from devsecops_radar.scanners.semgrep import SemgrepScanner
from devsecops_radar.scanners.trivy import TrivyScanner
from devsecops_radar.scanners.zizmor import ZizmorScanner

ALL_SCANNER_CLASSES: list[type] = [
    GitleaksScanner,
    PoutineScanner,
    SemgrepScanner,
    TrivyScanner,
    ZizmorScanner,
]


def _mock_safe_run_command(
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> MagicMock:
    mock = MagicMock(return_value=subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    ))
    return mock


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# Parse tests (parametrised for all scanners)
# ---------------------------------------------------------------------------
class TestParseCommon:
    @pytest.mark.parametrize("scanner_cls", ALL_SCANNER_CLASSES)
    def test_parse_valid_file(self, scanner_cls: type, tmp_path: Path) -> None:
        base = tmp_path / "base"
        base.mkdir()
        scanner = scanner_cls(allowed_base_dir=base)

        # Build minimal valid input per scanner
        if scanner_cls is GitleaksScanner:
            data: object = [{"RuleID": "G1", "File": "f.txt", "Description": "desc"}]
        elif scanner_cls is PoutineScanner:
            data = {
                "findings": [
                    {
                        "rule_id": "P1",
                        "severity": "HIGH",
                        "message": "test",
                        "location": {"file": "a.py", "line": 1},
                    }
                ]
            }
        elif scanner_cls is SemgrepScanner:
            data = {
                "results": [
                    {
                        "check_id": "S1",
                        "extra": {"severity": "WARNING", "message": "msg"},
                        "path": "f.py",
                        "start": {"line": 1},
                    }
                ]
            }
        elif scanner_cls is TrivyScanner:
            data = {
                "Results": [
                    {
                        "Target": "t",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-1",
                                "Severity": "HIGH",
                                "Title": "t",
                                "Description": "d",
                                "PkgName": "p",
                                "InstalledVersion": "1.0",
                                "FixedVersion": "2.0",
                            }
                        ],
                    }
                ]
            }
        else:  # ZizmorScanner
            data = [
                {
                    "id": "Z1",
                    "title": "Test",
                    "file": "f.yml",
                    "severity": "medium",
                    "description": "desc",
                    "line": 10,
                }
            ]

        report = base / "report.json"
        _write_json(report, data)
        findings = scanner.parse(str(report))
        assert isinstance(findings, list)
        assert len(findings) >= 1

    @pytest.mark.parametrize("scanner_cls", ALL_SCANNER_CLASSES)
    def test_parse_nonexistent_file_returns_empty(
        self, scanner_cls: type, tmp_path: Path
    ) -> None:
        base = tmp_path / "base"
        base.mkdir()
        scanner = scanner_cls(allowed_base_dir=base)
        findings = scanner.parse(str(base / "ghost.json"))
        assert findings == []

    @pytest.mark.parametrize("scanner_cls", ALL_SCANNER_CLASSES)
    def test_parse_path_outside_base_returns_empty(
        self, scanner_cls: type, tmp_path: Path
    ) -> None:
        base = tmp_path / "base"
        base.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        report = outside / "report.json"
        _write_json(report, [])
        scanner = scanner_cls(allowed_base_dir=base)
        findings = scanner.parse(str(report))
        assert findings == []


# ---------------------------------------------------------------------------
# Run tests (parametrised, mocked subprocess)
# ---------------------------------------------------------------------------
class TestRunCommon:
    @pytest.mark.parametrize("scanner_cls", ALL_SCANNER_CLASSES)
    def test_run_success_and_calls_parse(
        self, scanner_cls: type, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = tmp_path / "base"
        base.mkdir()
        target = base / "target.txt"
        target.write_text("test", encoding="utf-8")
        scanner = scanner_cls(allowed_base_dir=base)

        # Prepare valid stdout for each scanner
        if scanner_cls is GitleaksScanner:
            stdout = json.dumps([{"RuleID": "G1", "File": "t.txt", "Description": "d"}])
        elif scanner_cls is PoutineScanner:
            stdout = json.dumps(
                {
                    "findings": [
                        {
                            "rule_id": "P1",
                            "severity": "LOW",
                            "message": "m",
                            "location": {"file": "t.py", "line": 1},
                        }
                    ]
                }
            )
        elif scanner_cls is SemgrepScanner:
            stdout = json.dumps(
                {
                    "results": [
                        {
                            "check_id": "S1",
                            "extra": {"severity": "WARNING", "message": "m"},
                            "path": "t.py",
                            "start": {"line": 1},
                        }
                    ]
                }
            )
        elif scanner_cls is TrivyScanner:
            stdout = json.dumps(
                {
                    "Results": [
                        {
                            "Target": "t",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-1",
                                    "Severity": "HIGH",
                                    "Title": "t",
                                    "Description": "d",
                                    "PkgName": "p",
                                    "InstalledVersion": "1.0",
                                    "FixedVersion": "2.0",
                                }
                            ],
                        }
                    ]
                }
            )
        else:  # ZizmorScanner
            stdout = json.dumps(
                [
                    {
                        "id": "Z1",
                        "title": "Test",
                        "file": "f.yml",
                        "severity": "medium",
                        "description": "desc",
                        "line": 10,
                    }
                ]
            )

        monkeypatch.setattr(
            scanner, "_safe_run_command", _mock_safe_run_command(stdout=stdout)
        )
        findings = scanner.run(str(target))
        assert len(findings) >= 1

    @pytest.mark.parametrize("scanner_cls", ALL_SCANNER_CLASSES)
    def test_run_exception_returns_empty(
        self, scanner_cls: type, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = tmp_path / "base"
        base.mkdir()
        target = base / "target.txt"
        target.write_text("test", encoding="utf-8")
        scanner = scanner_cls(allowed_base_dir=base)
        monkeypatch.setattr(
            scanner,
            "_safe_run_command",
            MagicMock(side_effect=RuntimeError("fail")),
        )
        with pytest.raises(RuntimeError, match="fail"):
            scanner.run(str(target))


# ---------------------------------------------------------------------------
# Scanner‑specific tests
# ---------------------------------------------------------------------------
class TestZizmorParse:
    def test_valid_report(self, tmp_path: Path) -> None:
        base = tmp_path / "base"
        base.mkdir()
        scanner = ZizmorScanner(allowed_base_dir=base)
        data: list[dict[str, Any]] = [
            {
                "id": "Z1",
                "title": "Issue",
                "file": "ci.yml",
                "severity": "medium",
                "description": "desc",
                "line": 5,
            }
        ]
        report = base / "zizmor.json"
        _write_json(report, data)
        findings = scanner.parse(str(report))
        assert len(findings) == 1
        assert findings[0]["id"] == "Z1"

    def test_missing_location(self, tmp_path: Path) -> None:
        base = tmp_path / "base"
        base.mkdir()
        scanner = ZizmorScanner(allowed_base_dir=base)
        data: list[dict[str, Any]] = [
            {"id": "Z2", "title": "No file", "severity": "low", "description": "desc"}
        ]
        report = base / "noloc.json"
        _write_json(report, data)
        findings = scanner.parse(str(report))
        assert len(findings) == 1
        assert findings[0]["line"] is None


class TestTrivyRun:
    def test_run_image_rejected_invalid_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = tmp_path / "base"
        base.mkdir()
        scanner = TrivyScanner(allowed_base_dir=base)
        monkeypatch.setattr(scanner, "_safe_run_command", MagicMock())
        findings = scanner.run("-invalid:latest")
        assert findings == []

    def test_run_filesystem_target_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = tmp_path / "base"
        base.mkdir()
        target = base / "some" / "path"
        target.mkdir(parents=True, exist_ok=True)
        (target / "file").write_text("content", encoding="utf-8")
        scanner = TrivyScanner(allowed_base_dir=base)
        stdout = json.dumps({"Results": []})
        monkeypatch.setattr(
            scanner, "_safe_run_command", _mock_safe_run_command(stdout=stdout)
        )
        findings = scanner.run(str(target))
        assert findings == []

    def test_image_with_colon_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = tmp_path / "base"
        base.mkdir()
        scanner = TrivyScanner(allowed_base_dir=base)
        stdout = json.dumps(
            {
                "Results": [
                    {
                        "Target": "nginx:latest (debian 12)",
                        "Vulnerabilities": [],
                    }
                ]
            }
        )
        monkeypatch.setattr(
            scanner, "_safe_run_command", _mock_safe_run_command(stdout=stdout)
        )
        findings = scanner.run("nginx:latest")
        assert findings == []
