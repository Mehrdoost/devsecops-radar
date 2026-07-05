"""Tests for SBOM generation, dependency confusion detection, and VEX filtering."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from devsecops_radar.core.sbom import (
    apply_vex_filter,
    detect_dependency_confusion,
    generate_sbom,
)


class TestGenerateSbom:
    def test_path_not_safe_returns_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A path outside base_dir makes generate_sbom return None."""
        base = tmp_path / "base"
        base.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/syft")
        result = generate_sbom(str(outside), base_dir=base)
        assert result is None

    def test_creates_valid_cyclonedx(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = tmp_path / "base"
        base.mkdir()
        target = base / "target"
        target.mkdir()
        (target / "server.py").write_text("print('hello')")

        def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
            output_path = cmd[-1]
            Path(output_path).write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "components": [{"name": "/usr/src/app/server.py"}],
                    }
                )
            )
            return MagicMock()

        monkeypatch.setattr(
            "devsecops_radar.core.sbom.safe_subprocess_run", fake_run
        )
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/syft")

        result = generate_sbom(str(target), base_dir=base)
        assert result is not None
        assert result["components"][0]["name"] == "server.py"


class TestDetectDependencyConfusion:
    @pytest.fixture(autouse=True)
    def _mock_find_spec(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Ensure basic parsing is used by pretending requirements.parser is missing."""
        monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)

    def test_requirements_txt_finds_internal(self, tmp_path: Path) -> None:
        base = tmp_path / "base"
        base.mkdir()
        manifest = base / "requirements.txt"
        manifest.write_text("my-internal-pkg==1.0\nother-pkg==2.0")
        findings = detect_dependency_confusion(
            str(manifest),
            internal_prefixes=["my-"],
            base_dir=base,
        )
        assert len(findings) == 1
        assert findings[0]["package"] == "my-internal-pkg"

    def test_requirements_with_version_operators(self, tmp_path: Path) -> None:
        base = tmp_path / "base"
        base.mkdir()
        manifest = base / "requirements.txt"
        manifest.write_text("pkg-a>=1.0,<2.0\nnormal-pkg==1.0")
        findings = detect_dependency_confusion(
            str(manifest),
            internal_prefixes=["pkg-"],
            base_dir=base,
        )
        assert len(findings) == 1
        assert findings[0]["package"] == "pkg-a"

    def test_requirements_with_extras_and_markers(self, tmp_path: Path) -> None:
        base = tmp_path / "base"
        base.mkdir()
        manifest = base / "requirements.txt"
        manifest.write_text(
            "my-pkg[extra1,extra2]>=1.0; python_version < '3.10'"
        )
        findings = detect_dependency_confusion(
            str(manifest),
            internal_prefixes=["my-"],
            base_dir=base,
        )
        assert len(findings) == 1
        assert findings[0]["package"] == "my-pkg"

    def test_custom_prefixes(self, tmp_path: Path) -> None:
        base = tmp_path / "base"
        base.mkdir()
        manifest = base / "requirements.txt"
        manifest.write_text("company-pkg==1.0")
        findings = detect_dependency_confusion(
            str(manifest),
            internal_prefixes=["company-"],
            base_dir=base,
        )
        assert len(findings) == 1


class TestApplyVexFilter:
    def test_filters_not_affected(self, tmp_path: Path) -> None:
        findings = [
            {"id": "CVE-2024-0001", "severity": "HIGH"},
            {"id": "CVE-2024-0002", "severity": "MEDIUM"},
        ]
        vex = {"vulnerabilities": [{"id": "CVE-2024-0001", "analysis": {"state": "not_affected"}}]}
        vex_path = tmp_path / "vex.json"
        vex_path.write_text(json.dumps(vex), encoding="utf-8")
        filtered = apply_vex_filter(findings, str(vex_path), base_dir=tmp_path)
        assert len(filtered) == 1
        assert filtered[0]["id"] == "CVE-2024-0002"

    def test_no_filter_when_vex_missing(self) -> None:
        findings = [{"id": "X"}]
        assert apply_vex_filter(findings, "", base_dir=Path.cwd()) == findings
