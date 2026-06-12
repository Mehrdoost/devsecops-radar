"""Tests for SBOM generation and dependency analysis."""

import json
import subprocess
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger

from devsecops_radar.core.sbom import (
    _is_safe_path,
    _validate_file_size,
    apply_vex_filter,
    detect_dependency_confusion,
    generate_sbom,
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
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_syft_missing():
    """Simulate syft not installed."""
    with patch("shutil.which", return_value=None):
        yield


@pytest.fixture
def mock_syft_available():
    """Simulate syft available."""
    with patch("shutil.which", return_value="/usr/local/bin/syft"):
        yield


# ============================================================================
# Tests for _is_safe_path
# ============================================================================
class TestIsSafePath:
    def test_safe_path_inside_cwd(self, tmp_path):
        # Patch cwd to return tmp_path (a Path object)
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            assert _is_safe_path(str(tmp_path / "subdir")) is True

    def test_path_outside_cwd(self, tmp_path):
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            outside = Path(tmp_path.anchor) / "outside"
            assert _is_safe_path(str(outside)) is False

    def test_custom_base_dir(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        safe = base / "inside.txt"
        assert _is_safe_path(str(safe), base_dir=base) is True

        outside = tmp_path / "outside.txt"
        assert _is_safe_path(str(outside), base_dir=base) is False

    def test_exception_returns_false(self):
        with patch("pathlib.Path.resolve", side_effect=OSError("bad")):
            assert _is_safe_path("anything") is False


# ============================================================================
# Tests for _validate_file_size
# ============================================================================
class TestValidateFileSize:
    def test_small_file(self, tmp_path):
        f = tmp_path / "small.bin"
        f.write_bytes(b"x" * 1024)  # 1 KB
        assert _validate_file_size(f, max_size_mb=1) is True

    def test_file_exceeds_limit(self, tmp_path):
        f = tmp_path / "big.bin"
        f.write_bytes(b"x" * (2 * 1024 * 1024))  # 2 MB
        with capture_loguru() as msgs:
            assert _validate_file_size(f, max_size_mb=1) is False
        assert any("exceeds" in m for m in msgs)

    def test_cannot_stat(self, tmp_path):
        nonexistent = tmp_path / "nope.bin"
        with capture_loguru() as msgs:
            assert _validate_file_size(nonexistent) is False
        assert any("Cannot stat" in m for m in msgs)


# ============================================================================
# Tests for generate_sbom
# ============================================================================
class TestGenerateSbom:
    def test_path_not_safe(self, mock_syft_available):
        with patch("pathlib.Path.cwd", return_value=Path("/safe")):
            with capture_loguru() as msgs:
                result = generate_sbom("/etc/passwd")
        assert result is None
        assert any("outside allowed path" in m for m in msgs)

    def test_target_not_directory(self, mock_syft_available, tmp_path):
        f = tmp_path / "notadir"
        f.touch()
        with patch(
            "devsecops_radar.core.sbom._is_safe_path", return_value=True
        ):
            with capture_loguru() as msgs:
                result = generate_sbom(str(f))
        assert result is None
        assert any("does not exist" in m for m in msgs)

    def test_syft_missing(self, mock_syft_missing, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch(
            "devsecops_radar.core.sbom._is_safe_path", return_value=True
        ):
            with capture_loguru() as msgs:
                result = generate_sbom(str(target))
        assert result is None
        assert any("syft is not installed" in m for m in msgs)

    def test_syft_success(self, mock_syft_available, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        output = tmp_path / "sbom.json"
        sbom_data = {"bomFormat": "CycloneDX"}
        output.write_text(json.dumps(sbom_data))

        with patch("subprocess.run") as mock_run, patch(
            "pathlib.Path.cwd", return_value=tmp_path
        ):
            mock_run.return_value = MagicMock(returncode=0)
            result = generate_sbom(str(target), str(output))

        assert result == sbom_data
        mock_run.assert_called_once()

    def test_syft_process_error(self, mock_syft_available, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        output = tmp_path / "sbom.json"

        with patch("subprocess.run") as mock_run, patch(
            "pathlib.Path.cwd", return_value=tmp_path
        ):
            mock_run.side_effect = subprocess.CalledProcessError(
                1, "syft", stderr="error msg"
            )
            with capture_loguru() as msgs:
                result = generate_sbom(str(target), str(output))
        assert result is None
        assert any("syft failed" in m for m in msgs)

    def test_syft_timeout(self, mock_syft_available, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        output = tmp_path / "sbom.json"

        with patch("subprocess.run") as mock_run, patch(
            "pathlib.Path.cwd", return_value=tmp_path
        ):
            mock_run.side_effect = subprocess.TimeoutExpired("syft", 120)
            with capture_loguru() as msgs:
                result = generate_sbom(str(target), str(output))
        assert result is None
        assert any("timed out" in m for m in msgs)

    def test_output_file_missing_after_command(
        self, mock_syft_available, tmp_path
    ):
        target = tmp_path / "src"
        target.mkdir()
        output = tmp_path / "missing.json"

        with patch("subprocess.run") as mock_run, patch(
            "pathlib.Path.cwd", return_value=tmp_path
        ):
            mock_run.return_value = MagicMock(returncode=0)
            with capture_loguru() as msgs:
                result = generate_sbom(str(target), str(output))
        assert result is None
        assert any("not created" in m for m in msgs)

    def test_output_file_too_large(self, mock_syft_available, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        output = tmp_path / "sbom.json"

        with patch(
            "devsecops_radar.core.sbom._validate_file_size", return_value=False
        ), patch("subprocess.run"), patch("pathlib.Path.cwd", return_value=tmp_path):
            result = generate_sbom(str(target), str(output))
        assert result is None


# ============================================================================
# Tests for detect_dependency_confusion
# ============================================================================
class TestDetectDependencyConfusion:
    def test_unsafe_path(self):
        with patch("pathlib.Path.cwd", return_value=Path("/safe")):
            with capture_loguru() as msgs:
                result = detect_dependency_confusion("/etc/passwd")
        assert result == []
        assert any("Blocked reading manifest" in m for m in msgs)

    def test_missing_file(self, tmp_path):
        path = str(tmp_path / "nonexistent.json")
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            with capture_loguru() as msgs:
                result = detect_dependency_confusion(path)
        assert result == []
        assert any("Manifest file not found" in m for m in msgs)

    def test_package_json(self, tmp_path):
        manifest = tmp_path / "package.json"
        manifest.write_text(
            json.dumps(
                {
                    "dependencies": {"mycompany-utils": "1.0", "express": "4.0"},
                    "devDependencies": {"internal-lib": "2.0"},
                }
            )
        )
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            result = detect_dependency_confusion(str(manifest))
        assert len(result) == 2
        assert result[0]["package"] == "mycompany-utils"
        assert result[1]["package"] == "internal-lib"

    def test_package_json_no_internal(self, tmp_path):
        manifest = tmp_path / "package.json"
        manifest.write_text(json.dumps({"dependencies": {"express": "4.0"}}))
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            result = detect_dependency_confusion(str(manifest))
        assert result == []

    def test_package_json_invalid(self, tmp_path):
        manifest = tmp_path / "package.json"
        manifest.write_text("not json")
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            with capture_loguru() as msgs:
                result = detect_dependency_confusion(str(manifest))
        assert result == []
        assert any("Invalid JSON" in m for m in msgs)

    def test_requirements_txt(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text(
            "# comment\nmycompany-auth==1.0\ninternal-tools>=2.0\ndjango==3.2\n"
        )
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            result = detect_dependency_confusion(str(manifest))
        assert len(result) == 2
        assert result[0]["package"] == "mycompany-auth"
        assert result[1]["package"] == "internal-tools"

    def test_requirements_txt_no_internal(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("django==3.2\nflask>=2.0\n")
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            result = detect_dependency_confusion(str(manifest))
        assert result == []

    def test_requirements_with_version_operators(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("mycompany-lib<=1.5,!=1.4\nother\n")
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            result = detect_dependency_confusion(str(manifest))
        assert len(result) == 1
        assert result[0]["package"] == "mycompany-lib"

    def test_unsupported_format(self, tmp_path):
        manifest = tmp_path / "Pipfile"
        manifest.write_text("[packages]")
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            with capture_loguru() as msgs:
                result = detect_dependency_confusion(str(manifest))
        assert result == []
        assert any("Unsupported manifest" in m for m in msgs)

    def test_custom_prefixes(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("custom-lib==1.0\n")
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            result = detect_dependency_confusion(
                str(manifest), internal_prefixes=["custom-"]
            )
        assert len(result) == 1
        assert result[0]["package"] == "custom-lib"


# ============================================================================
# Tests for apply_vex_filter
# ============================================================================
class TestApplyVexFilter:
    def test_empty_vex_path(self):
        findings = [{"id": "CVE-123"}]
        assert apply_vex_filter(findings, "") == findings

    def test_missing_vex_file(self):
        findings = [{"id": "CVE-123"}]
        assert apply_vex_filter(findings, "/nonexistent.json") == findings

    def test_unsafe_vex_path(self, tmp_path):
        # Create a real file so os.path.exists returns True
        vex_file = tmp_path / "vex.json"
        vex_file.write_text("{}")
        with patch(
            "devsecops_radar.core.sbom._is_safe_path", return_value=False
        ):
            with capture_loguru() as msgs:
                result = apply_vex_filter(
                    [{"id": "CVE-123"}], str(vex_file)
                )
        assert result == [{"id": "CVE-123"}]
        assert any("path is not allowed" in m for m in msgs)

    def test_valid_vex(self, tmp_path):
        vex = tmp_path / "vex.json"
        vex.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "id": "CVE-2024-1111",
                            "analysis": {"state": "not_affected"},
                        },
                        {
                            "id": "CVE-2024-2222",
                            "analysis": {"state": "false_positive"},
                        },
                    ]
                }
            )
        )
        findings = [
            {"id": "CVE-2024-1111"},
            {"id": "CVE-2024-3333"},
            {"id": "CVE-2024-2222"},
        ]
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            with capture_loguru() as msgs:
                result = apply_vex_filter(findings, str(vex))
        assert len(result) == 1
        assert result[0]["id"] == "CVE-2024-3333"
        assert any("2 findings excluded" in m for m in msgs)

    def test_vex_with_no_matching_exclusions(self, tmp_path):
        vex = tmp_path / "vex.json"
        vex.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "id": "OTHER",
                            "analysis": {"state": "resolved"},
                        }
                    ]
                }
            )
        )
        findings = [{"id": "CVE-123"}]
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            result = apply_vex_filter(findings, str(vex))
        assert result == findings

    def test_vex_invalid_json(self, tmp_path):
        vex = tmp_path / "vex.json"
        vex.write_text("not json")
        findings = [{"id": "CVE-123"}]
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            with capture_loguru() as msgs:
                result = apply_vex_filter(findings, str(vex))
        assert result == findings
        assert any("Failed to read VEX" in m for m in msgs)
