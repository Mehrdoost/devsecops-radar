"""Tests for the automated patching engine and Git PR generation.

Covers successful single‑line patches, evidence matching, rollback on
failure, missing target detection, and the Git PR workflow.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from devsecops_radar.core.remediation import apply_patch, generate_pr


# ---------------------------------------------------------------------------
# Shared mocked dependencies – applied automatically before every test
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _patch_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace filesystem and subprocess calls with safe mocks."""
    monkeypatch.setattr(
        "devsecops_radar.core.remediation.resolve_safe_path",
        lambda p, base: Path(p).resolve(),
    )
    monkeypatch.setattr(
        "devsecops_radar.core.remediation.atomic_write",
        MagicMock(),
    )
    monkeypatch.setattr(
        "devsecops_radar.core.remediation._backup_file",
        MagicMock(return_value=Path("/fake/backup.bak")),
    )


class TestApplyPatch:
    """Test the apply_patch function with various scenarios."""

    @pytest.fixture(autouse=True)
    def _setup_mock_safe_read_open(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Replace safe_read_open with a helper that returns pre‑stored content."""
        self._file_contents: dict[str, str] = {}

        def _open_file(path: str, base_dir=None) -> MagicMock:
            content = self._file_contents.get(str(Path(path)), "")
            mock_file = MagicMock()
            mock_file.__enter__.return_value = mock_file
            mock_file.__exit__.return_value = None
            mock_file.readlines.return_value = content.splitlines(keepends=True)
            mock_file.read.return_value = content
            return mock_file

        monkeypatch.setattr(
            "devsecops_radar.core.remediation.safe_read_open",
            _open_file,
        )

    def _prepare_file(self, path: Path, content: str) -> None:
        """Create a real file on disk AND store content for the mocked reader."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self._file_contents[str(path)] = content

    def test_successful_single_line_patch_no_evidence(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        target = tmp_path / "script.py"
        self._prepare_file(target, "original line\n")
        finding = {"target": str(target), "line": 1}

        mock_run = MagicMock(return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        ))
        monkeypatch.setattr(
            "devsecops_radar.core.remediation.safe_subprocess_run",
            mock_run,
        )

        result = apply_patch(finding,
                             "@@ -1,1 +1,1 @@\n-original line\n+patched line\n",
                             base_dir=tmp_path, require_evidence=False)
        assert result is True
        assert mock_run.call_count >= 2  # dry-run + actual apply

    def test_evidence_match_applies(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        target = tmp_path / "config.cfg"
        self._prepare_file(target, "password=secret123\n")
        finding = {"target": str(target), "line": 1, "evidence": "password=secret123"}

        mock_run = MagicMock(return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        ))
        monkeypatch.setattr(
            "devsecops_radar.core.remediation.safe_subprocess_run",
            mock_run,
        )

        result = apply_patch(finding,
                             "@@ -1,1 +1,1 @@\n-password=secret123\n+password=redacted\n",
                             base_dir=tmp_path)
        assert result is True

    def test_line_out_of_bounds(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        target = tmp_path / "empty.txt"
        self._prepare_file(target, "")
        finding = {"target": str(target), "line": 10, "evidence": "anything"}

        result = apply_patch(finding, "dummy patch", base_dir=tmp_path)
        assert result is False

    def test_patch_failure_rolls_back(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        target = tmp_path / "code.py"
        self._prepare_file(target, "original\n")
        finding = {"target": str(target)}

        mock_run = MagicMock(side_effect=[
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            subprocess.CompletedProcess([], 1, stdout="", stderr="error"),
        ])
        monkeypatch.setattr(
            "devsecops_radar.core.remediation.safe_subprocess_run",
            mock_run,
        )

        result = apply_patch(finding, "invalid patch", base_dir=tmp_path,
                             require_evidence=False)
        assert result is False

    def test_invalid_line_number_uses_default(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        target = tmp_path / "file.txt"
        self._prepare_file(target, "line1\nline2\n")
        finding = {"target": str(target), "line": "not-a-number"}

        mock_run = MagicMock(return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        ))
        monkeypatch.setattr(
            "devsecops_radar.core.remediation.safe_subprocess_run",
            mock_run,
        )

        result = apply_patch(finding,
                             "@@ -1,1 +1,1 @@\n-line1\n+new\n",
                             base_dir=tmp_path, require_evidence=False)
        assert result is True

    def test_missing_target_is_rejected(self) -> None:
        finding: dict = {"line": 1}
        assert apply_patch(finding, "patch", base_dir=Path.cwd()) is False


class TestGeneratePr:
    """Test Git PR generation with mocked subprocess calls."""

    @pytest.fixture(autouse=True)
    def _mock_git(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(
            "devsecops_radar.core.remediation.resolve_safe_path",
            lambda p, base: Path(p).resolve(),
        )
        self.run_mock = MagicMock()
        monkeypatch.setattr(
            "devsecops_radar.core.remediation.safe_subprocess_run",
            self.run_mock,
        )
        self.tmp_path = tmp_path

    def test_successful_pr_and_push(self) -> None:
        self.run_mock.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=str(self.tmp_path)),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 0, stdout="main\n"),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0),
        ]
        generate_pr({"modified.py"}, base_dir=self.tmp_path)
        assert self.run_mock.call_count >= 7

    def test_push_fails_stores_patch_locally(self) -> None:
        self.run_mock.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=str(self.tmp_path)),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 0, stdout="main"),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0),
            subprocess.CalledProcessError(1, "push"),
            subprocess.CompletedProcess([], 0),
        ]
        generate_pr({"file.py"}, base_dir=self.tmp_path)
        # The format-patch call is made after push failure
        assert self.run_mock.call_count >= 8

    def test_git_failure_during_checkout(self) -> None:
        self.run_mock.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=str(self.tmp_path)),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 0, stdout="main"),
            subprocess.CalledProcessError(1, "checkout"),
        ]
        with patch("devsecops_radar.core.remediation.logger.error") as mock_log:
            generate_pr({"x.py"}, base_dir=self.tmp_path)
            mock_log.assert_called()
