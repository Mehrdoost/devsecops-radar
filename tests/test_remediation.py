"""Tests for remediation module (updated for require_evidence, sorted auto_fix, new generate_pr)."""

import subprocess
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest
from loguru import logger

from devsecops_radar.core.remediation import (
    _backup_file,
    _init_dirs,
    apply_patch,
    auto_fix,
    generate_pr,
    generate_remediation_guide,
)


# ---------------------------------------------------------------------------
# Capture loguru output
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
# Helper fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def backup_and_patch_dirs(tmp_path, monkeypatch):
    fake_backup = tmp_path / "backups"
    fake_patch = tmp_path / "patches"
    monkeypatch.setattr("devsecops_radar.core.remediation.BACKUP_DIR", fake_backup)
    monkeypatch.setattr("devsecops_radar.core.remediation.PATCH_DIR", fake_patch)
    return fake_backup, fake_patch


# ============================================================================
# Tests for _init_dirs
# ============================================================================
class TestInitDirs:
    def test_creates_directories(self, backup_and_patch_dirs):
        fake_backup, fake_patch = backup_and_patch_dirs
        assert not fake_backup.exists()
        assert not fake_patch.exists()
        _init_dirs()
        assert fake_backup.exists()
        assert fake_patch.exists()

    def test_idempotent(self, backup_and_patch_dirs):
        _init_dirs()
        _init_dirs()


# ============================================================================
# Tests for _backup_file
# ============================================================================
class TestBackupFile:
    def test_successful_backup(self, backup_and_patch_dirs, tmp_path):
        fake_backup, _ = backup_and_patch_dirs
        source = tmp_path / "src.py"
        source.write_text("original code")

        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            return_value=source,
        ):
            m = mock_open(read_data="original code")
            with patch("devsecops_radar.core.remediation.safe_read_open", m):
                with patch(
                    "devsecops_radar.core.remediation.atomic_write"
                ) as mock_atomic:
                    result = _backup_file(str(source), base_dir=tmp_path)

        assert result is not None
        mock_atomic.assert_called_once()
        call_args = mock_atomic.call_args[0][0]
        assert call_args.parent == fake_backup

    def test_source_not_exist(self, backup_and_patch_dirs, tmp_path):
        missing = tmp_path / "missing.txt"
        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            side_effect=ValueError("outside"),
        ):
            result = _backup_file(str(missing))
        assert result is None

    def test_backup_failure_during_write(self, backup_and_patch_dirs, tmp_path):
        source = tmp_path / "src.py"
        source.write_text("code")
        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            return_value=source,
        ):
            m = mock_open(read_data="code")
            with patch("devsecops_radar.core.remediation.safe_read_open", m):
                with patch(
                    "devsecops_radar.core.remediation.atomic_write",
                    side_effect=OSError("disk full"),
                ):
                    with capture_loguru() as msgs:
                        result = _backup_file(str(source), base_dir=tmp_path)
        assert result is None
        assert any("Backup failed" in m for m in msgs)


# ============================================================================
# Tests for apply_patch
# ============================================================================
class TestApplyPatch:
    @pytest.fixture
    def target_file(self, tmp_path):
        f = tmp_path / "target.py"
        f.write_text("line0\nline1\nline2\nline3\n")
        return f

    @pytest.fixture
    def finding(self, target_file):
        return {"target": str(target_file), "line": 2, "id": "F1"}

    def test_missing_target_or_line(self, tmp_path):
        with capture_loguru() as msgs:
            assert apply_patch({"target": "", "line": 1}, "patch", base_dir=tmp_path) is False
        assert any("missing" in m for m in msgs)

    def test_invalid_line_number(self, tmp_path, target_file):
        with capture_loguru() as msgs:
            assert apply_patch(
                {"target": str(target_file), "line": "abc"}, "patch", base_dir=tmp_path
            ) is False
        assert any("Invalid line number" in m for m in msgs)

    def test_unsafe_path(self, tmp_path):
        outside = tmp_path.parent / "outside.txt"
        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            side_effect=ValueError("outside allowed directory"),
        ):
            with capture_loguru() as msgs:
                assert apply_patch(
                    {"target": str(outside), "line": 1}, "patch", base_dir=tmp_path
                ) is False
            assert any("Security Error" in m for m in msgs)

    def test_target_file_not_exist(self, tmp_path):
        missing = tmp_path / "missing.txt"
        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            return_value=missing,
        ):
            with capture_loguru() as msgs:
                assert apply_patch(
                    {"target": str(missing), "line": 1}, "patch", base_dir=tmp_path
                ) is False
            assert any("does not exist" in m for m in msgs)

    def test_empty_patch(self, target_file, finding, tmp_path):
        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            return_value=target_file,
        ):
            with capture_loguru() as msgs:
                assert apply_patch(finding, "", base_dir=tmp_path) is False
            assert any("Patch content is empty" in m for m in msgs)

    def test_successful_single_line_patch_no_evidence(self, target_file, finding, tmp_path):
        original_content = "line0\nline1\nline2\nline3\n"
        m_read = mock_open(read_data=original_content)

        mock_file = MagicMock()
        mock_atomic = MagicMock()
        mock_atomic.return_value.__enter__.return_value = mock_file

        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            return_value=target_file,
        ):
            with patch("devsecops_radar.core.remediation.safe_read_open", m_read):
                with patch("devsecops_radar.core.remediation.atomic_write", mock_atomic):
                    with patch(
                        "devsecops_radar.core.remediation._backup_file",
                        return_value=Path("/fake/backup.py"),
                    ):
                        with capture_loguru() as msgs:
                            result = apply_patch(finding, "new line\n", base_dir=tmp_path)

        assert result is True
        assert any("Successfully patched" in m for m in msgs)
        mock_atomic.assert_called_once()
        written = mock_file.writelines.call_args[0][0]
        assert written[1] == "new line\n"

    def test_evidence_match_applies(self, target_file, tmp_path):
        # Evidence matches the current line
        finding = {
            "target": str(target_file),
            "line": 2,
            "evidence": "line1",
        }
        original_content = "line0\nline1\nline2\nline3\n"
        m_read = mock_open(read_data=original_content)
        mock_file = MagicMock()
        mock_atomic = MagicMock()
        mock_atomic.return_value.__enter__.return_value = mock_file

        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            return_value=target_file,
        ):
            with patch("devsecops_radar.core.remediation.safe_read_open", m_read):
                with patch("devsecops_radar.core.remediation.atomic_write", mock_atomic):
                    with patch(
                        "devsecops_radar.core.remediation._backup_file",
                        return_value=Path("/fake/backup.py"),
                    ):
                        result = apply_patch(finding, "new line\n", base_dir=tmp_path, require_evidence=True)

        assert result is True
        mock_atomic.assert_called_once()

    def test_evidence_mismatch_rejects(self, target_file, tmp_path):
        finding = {
            "target": str(target_file),
            "line": 2,
            "evidence": "WRONG",
        }
        original_content = "line0\nline1\nline2\nline3\n"
        m_read = mock_open(read_data=original_content)

        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            return_value=target_file,
        ):
            with patch("devsecops_radar.core.remediation.safe_read_open", m_read):
                with patch(
                    "devsecops_radar.core.remediation.atomic_write"
                ) as mock_atomic:
                    with capture_loguru() as msgs:
                        result = apply_patch(finding, "new line\n", base_dir=tmp_path)

        assert result is False
        assert any("Evidence mismatch" in m for m in msgs)
        mock_atomic.assert_not_called()

    def test_require_evidence_but_missing(self, target_file, tmp_path):
        finding = {"target": str(target_file), "line": 2}
        original_content = "line0\nline1\nline2\nline3\n"
        m_read = mock_open(read_data=original_content)

        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            return_value=target_file,
        ):
            with patch("devsecops_radar.core.remediation.safe_read_open", m_read):
                with patch(
                    "devsecops_radar.core.remediation.atomic_write"
                ) as mock_atomic:
                    with capture_loguru() as msgs:
                        result = apply_patch(finding, "new line\n", base_dir=tmp_path, require_evidence=True)

        assert result is False
        assert any("No evidence provided" in m for m in msgs)
        mock_atomic.assert_not_called()

    def test_line_out_of_bounds(self, target_file, tmp_path):
        finding = {"target": str(target_file), "line": 10}
        original_content = "line0\nline1\nline2\nline3\n"
        m_read = mock_open(read_data=original_content)

        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            return_value=target_file,
        ):
            with patch("devsecops_radar.core.remediation.safe_read_open", m_read):
                with patch(
                    "devsecops_radar.core.remediation.atomic_write"
                ) as mock_atomic:
                    with capture_loguru() as msgs:
                        result = apply_patch(finding, "patch", base_dir=tmp_path)

        assert result is False
        assert any("out of bounds" in m for m in msgs)
        mock_atomic.assert_not_called()

    def test_patch_failure_rolls_back(self, target_file, finding, tmp_path):
        original_content = "line0\nline1\nline2\nline3\n"
        m_read = mock_open(read_data=original_content)
        backup = target_file.parent / "backup.py"
        backup.write_text("backup data")

        mock_atomic = MagicMock()
        mock_atomic.side_effect = OSError("replace failed")

        with patch(
            "devsecops_radar.core.remediation.resolve_safe_path",
            return_value=target_file,
        ):
            with patch("devsecops_radar.core.remediation.safe_read_open", m_read):
                with patch("devsecops_radar.core.remediation.atomic_write", mock_atomic):
                    with patch(
                        "devsecops_radar.core.remediation._backup_file",
                        return_value=backup,
                    ):
                        with patch("shutil.copy2") as mock_copy:
                            with capture_loguru() as msgs:
                                result = apply_patch(finding, "newline\n", base_dir=tmp_path)

        assert result is False
        assert any("Atomic write failed" in m for m in msgs)
        mock_copy.assert_called_once_with(str(backup), str(target_file))


# ============================================================================
# Tests for generate_remediation_guide
# ============================================================================
class TestGenerateRemediationGuide:
    def test_empty(self):
        guide = generate_remediation_guide([])
        assert "No automated remediations" in guide

    def test_single_with_steps(self):
        rems = [
            {
                "finding_id": "F1",
                "title": "Fix SQLi",
                "remediation_steps": ["Step one", "Step two"],
            }
        ]
        guide = generate_remediation_guide(rems)
        assert "F1" in guide
        assert "Fix SQLi" in guide
        assert "1. Step one" in guide
        assert "2. Step two" in guide

    def test_missing_steps(self):
        rems = [{"finding_id": "F1", "title": "Fix"}]
        guide = generate_remediation_guide(rems)
        assert "Manual investigation required" in guide


# ============================================================================
# Tests for auto_fix
# ============================================================================
class TestAutoFix:
    def test_applies_matching_patches(self):
        findings = [
            {"id": "VULN-1", "target": "a.py", "line": 1},
            {"id": "VULN-2", "target": "b.py", "line": 1},
        ]
        ai_summary = {
            "top_remediations": [
                {"finding_id": "VULN-1", "patch_content": "fix1"},
                {"finding_id": "VULN-2", "patch_content": "fix2"},
            ]
        }
        with patch(
            "devsecops_radar.core.remediation.apply_patch", return_value=True
        ) as mock_apply:
            modified = auto_fix(findings, ai_summary)
        assert modified == {"a.py", "b.py"}
        assert mock_apply.call_count == 2

    def test_skips_missing_patch(self):
        findings = [{"id": "VULN-1", "target": "a.py", "line": 1}]
        ai_summary = {
            "top_remediations": [
                {"finding_id": "VULN-1"}  # no patch_content
            ]
        }
        with patch("devsecops_radar.core.remediation.apply_patch") as mock_apply:
            modified = auto_fix(findings, ai_summary)
        assert modified == set()
        mock_apply.assert_not_called()

    def test_handles_apply_failure(self):
        findings = [{"id": "VULN-1", "target": "a.py", "line": 1}]
        ai_summary = {
            "top_remediations": [
                {"finding_id": "VULN-1", "patch_content": "fix"}
            ]
        }
        with patch(
            "devsecops_radar.core.remediation.apply_patch", return_value=False
        ):
            modified = auto_fix(findings, ai_summary)
        assert modified == set()

    def test_sorts_findings_descending_by_line(self):
        findings = [
            {"id": "VULN-1", "target": "a.py", "line": 100},
            {"id": "VULN-2", "target": "a.py", "line": 50},
            {"id": "VULN-3", "target": "b.py", "line": 200},
        ]
        ai_summary = {
            "top_remediations": [
                {"finding_id": "VULN-1", "patch_content": "fix1"},
                {"finding_id": "VULN-2", "patch_content": "fix2"},
                {"finding_id": "VULN-3", "patch_content": "fix3"},
            ]
        }
        call_order = []
        def side_effect(finding, patch_content, **kwargs):
            call_order.append(finding["id"])
            return True

        with patch(
            "devsecops_radar.core.remediation.apply_patch", side_effect=side_effect
        ):
            auto_fix(findings, ai_summary)

        # Should be applied in descending line order: 200, 100, 50
        assert call_order == ["VULN-3", "VULN-1", "VULN-2"]


# ============================================================================
# Tests for generate_pr
# ============================================================================
class TestGeneratePr:
    def test_no_modified_files(self):
        with capture_loguru() as msgs:
            generate_pr(set())
        assert any("No files were modified" in m for m in msgs)

    def test_invalid_branch_name(self):
        with capture_loguru() as msgs:
            generate_pr({"file.txt"}, branch="bad;branch")
        assert any("Invalid branch name" in m for m in msgs)

    def test_not_a_git_repo(self):
        with patch(
            "devsecops_radar.core.remediation.safe_subprocess_run",
            side_effect=subprocess.CalledProcessError(1, "git", stderr="fatal"),
        ), capture_loguru() as msgs:
            generate_pr({"file.txt"}, branch="fix")
        assert any("Not a git repository" in m for m in msgs)

    def test_successful_pr_and_push(self):
        with patch(
            "devsecops_radar.core.remediation.safe_subprocess_run"
        ) as mock_run:
            mock_run.side_effect = [
                MagicMock(),                   # git rev-parse (success)
                None,                          # git add file
                None,                          # git checkout -b ...
                None,                          # git commit
                None,                          # git push
            ]
            with capture_loguru() as msgs:
                generate_pr({"a.txt"}, branch="fix-branch")

        assert mock_run.call_count == 5
        calls = [call[0][0] for call in mock_run.call_args_list]
        assert calls[0] == ["git", "rev-parse", "--show-toplevel"]
        assert calls[1] == ["git", "add", "a.txt"]
        assert "fix-branch-" in calls[2][3]  # branch with timestamp
        assert calls[3][:3] == ["git", "commit", "-m"]
        assert calls[4][:4] == ["git", "push", "-u", "origin"]
        assert any("Pushed automated fixes to branch" in m for m in msgs)

    def test_push_fails_stores_patch_locally(self, backup_and_patch_dirs):
        _, fake_patch = backup_and_patch_dirs
        with patch(
            "devsecops_radar.core.remediation.safe_subprocess_run"
        ) as mock_run:
            mock_run.side_effect = [
                MagicMock(),                          # git rev-parse (ok)
                None,                                 # git add
                None,                                 # git checkout
                None,                                 # git commit
                subprocess.CalledProcessError(1, "git push"),  # push fails
                None,                                 # format-patch
            ]
            with capture_loguru():
                generate_pr({"a.txt"}, branch="fix-branch")
        assert mock_run.call_count == 6
        format_patch_call = mock_run.call_args_list[5][0][0]
        assert "format-patch" in format_patch_call
        assert str(fake_patch) in format_patch_call

    def test_git_failure_during_checkout(self):
        with patch(
            "devsecops_radar.core.remediation.safe_subprocess_run"
        ) as mock_run:
            mock_run.side_effect = [
                MagicMock(),                          # git rev-parse (ok)
                None,                                 # git add
                subprocess.CalledProcessError(1, "git checkout", stderr="fatal"),
            ]
            with capture_loguru() as msgs:
                generate_pr({"file.txt"}, branch="fix")
        assert any("Git operation failed" in m and "fatal" in m for m in msgs)

    def test_git_not_found(self):
        with patch(
            "devsecops_radar.core.remediation.safe_subprocess_run",
            side_effect=FileNotFoundError,
        ), capture_loguru() as msgs:
            generate_pr({"file.txt"}, branch="fix")
        assert any("Git executable not found" in m for m in msgs)
