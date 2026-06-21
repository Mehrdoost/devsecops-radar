"""Tests for SBOM generation and dependency analysis – updated for atomic write and base_dir."""

import json
import subprocess
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger

from devsecops_radar.core.sbom import (
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
    with patch("shutil.which", return_value=None):
        yield


@pytest.fixture
def mock_syft_available():
    with patch("shutil.which", return_value="/usr/local/bin/syft"):
        yield


# ============================================================================
# Tests for _validate_file_size (unchanged helper)
# ============================================================================
class TestValidateFileSize:
    def test_small_file(self, tmp_path):
        f = tmp_path / "small.bin"
        f.write_bytes(b"x" * 1024)
        assert _validate_file_size(f, max_size_mb=1) is True

    def test_file_exceeds_limit(self, tmp_path):
        f = tmp_path / "big.bin"
        f.write_bytes(b"x" * (2 * 1024 * 1024))
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
        # Path outside the allowed directory should cause ValueError and return None
        with patch("pathlib.Path.cwd", return_value=Path("/safe")):
            with capture_loguru() as msgs:
                result = generate_sbom("/etc/passwd")
        assert result is None
        assert any("blocked" in m.lower() for m in msgs)

    def test_target_not_directory(self, mock_syft_available, tmp_path):
        f = tmp_path / "notadir"
        f.touch()
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            with capture_loguru() as msgs:
                result = generate_sbom(str(f))
        assert result is None
        assert any("does not exist" in m for m in msgs)

    def test_syft_missing(self, mock_syft_missing, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            with capture_loguru() as msgs:
                result = generate_sbom(str(target))
        assert result is None
        assert any("syft is not installed" in m for m in msgs)

    def test_syft_success(self, mock_syft_available, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        output = tmp_path / "sbom.json"
        sbom_data = {"bomFormat": "CycloneDX"}
        # pre-create the output so the final read succeeds
        output.write_text(json.dumps(sbom_data))

        tmp_output = output.with_name(f".tmp-{output.name}")
        # Simulate syft writing to the tmp file
        tmp_output.write_text(json.dumps(sbom_data))

        with patch("subprocess.run") as mock_run, patch(
            "pathlib.Path.cwd", return_value=tmp_path
        ):
            mock_run.return_value = MagicMock(returncode=0)
            result = generate_sbom(str(target), str(output))

        assert result == sbom_data
        mock_run.assert_called_once()
        # The tmp file should be replaced to the final output
        assert output.exists()

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
        # Pre-create the tmp output so that it exists and is large
        tmp_output = output.with_name(f".tmp-{output.name}")
        tmp_output.write_bytes(b"x" * (51 * 1024 * 1024))  # 51 MB

        with patch("subprocess.run") as mock_run, patch(
            "pathlib.Path.cwd", return_value=tmp_path
        ):
            mock_run.return_value = MagicMock(returncode=0)
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
        assert any("Cannot read manifest" in m for m in msgs)

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

    def test_requirements_with_extras_and_markers(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("mycompany-lib[extra]>=1.0;python_version>'3.8'\n")
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
        vex_file = tmp_path / "vex.json"
        vex_file.write_text("{}")
        with patch(
            "devsecops_radar.core.path_security.resolve_safe_path",
            side_effect=ValueError("outside allowed"),
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
        assert any("VEX file path is not allowed" in m for m in msgs)
