"""Tests for remediation module (updated with safe_subprocess_run, UUID backups, multiline patches)."""

import os
import subprocess
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from devsecops_radar.core.remediation import (
    BACKUP_DIR,
    PATCH_DIR,
    _backup_file,
    _init_dirs,
    _is_safe_path,
    apply_patch,
    auto_fix,
    generate_pr,
    generate_remediation_guide,
)
from loguru import logger


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
    """Redirect BACKUP_DIR and PATCH_DIR to temporary locations."""
    fake_backup = tmp_path / "backups"
    fake_patch = tmp_path / "patches"
    monkeypatch.setattr(
        "devsecops_radar.core.remediation.BACKUP_DIR", fake_backup
    )
    monkeypatch.setattr(
        "devsecops_radar.core.remediation.PATCH_DIR", fake_patch
    )
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
        _init_dirs()  # should not raise


# ============================================================================
# Tests for _is_safe_path
# ============================================================================
class TestIsSafePath:
    def test_safe_path(self, tmp_path):
        p = tmp_path / "file.txt"
        p.touch()
        assert _is_safe_path(str(p), base_dir=tmp_path) is True

    def test_traversal_detected(self, tmp_path):
        outside = tmp_path.parent / "outside.txt"
        assert _is_safe_path(str(outside), base_dir=tmp_path) is False

    def test_default_base_cwd(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        inside = tmp_path / "inside.txt"
        assert _is_safe_path(str(inside)) is True

    def test_resolution_error(self):
        with patch("pathlib.Path.resolve", side_effect=OSError("bad")):
            with capture_loguru() as msgs:
                assert _is_safe_path("file.txt") is False
            assert any("Path resolution error" in m for m in msgs)


# ============================================================================
# Tests for _backup_file
# ============================================================================
class TestBackupFile:
    def test_successful_backup(self, backup_and_patch_dirs, tmp_path):
        fake_backup, _ = backup_and_patch_dirs
        source = tmp_path / "src.py"
        source.write_text("original code")
        # Stable UUID for predictable assertion
        with patch.object(uuid, "uuid4", return_value=uuid.UUID("12345678123456781234567812345678")):
            with patch("devsecops_radar.core.remediation.Path.cwd", return_value=tmp_path):
                with patch("shutil.copy2") as mock_copy:
                    result = _backup_file(str(source))
        assert result is not None
        mock_copy.assert_called_once()
        args, _ = mock_copy.call_args
        # Check the backup file name contains the UUID and the relative path
        assert "12345678123456781234567812345678" in str(args[1])
        assert str(args[1]).endswith(".bak")

    def test_source_not_exist(self, backup_and_patch_dirs, tmp_path):
        missing = tmp_path / "missing.txt"
        result = _backup_file(str(missing))
        assert result is None

    def test_backup_failure(self, backup_and_patch_dirs, tmp_path):
        source = tmp_path / "src.py"
        source.write_text("code")
        with patch("devsecops_radar.core.remediation.Path.cwd", return_value=tmp_path):
            with patch("shutil.copy2", side_effect=OSError("disk full")):
                with capture_loguru() as msgs:
                    result = _backup_file(str(source))
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
        with capture_loguru() as msgs:
            assert apply_patch(
                {"target": str(outside), "line": 1}, "patch", base_dir=tmp_path
            ) is False
        assert any("outside the allowed directory" in m for m in msgs)

    def test_target_file_not_exist(self, tmp_path):
        missing = tmp_path / "missing.txt"
        with capture_loguru() as msgs:
            assert apply_patch(
                {"target": str(missing), "line": 1}, "patch", base_dir=tmp_path
            ) is False
        assert any("does not exist" in m for m in msgs)

    def test_empty_patch(self, target_file, finding, tmp_path):
        with capture_loguru() as msgs:
            assert apply_patch(finding, "", base_dir=tmp_path) is False
        assert any("Patch content is empty" in m for m in msgs)

    def test_successful_single_line_patch(self, target_file, finding, tmp_path):
        mock_fd = 123
        mock_tmp = target_file.parent / "tmpfile"
        m_open = mock_open(read_data="line0\nline1\nline2\nline3\n")
        # Create a mock that correctly simulates the context manager for os.fdopen
        mock_tf = MagicMock()
        mock_fdopen = MagicMock()
        mock_fdopen.return_value.__enter__.return_value = mock_tf

        with patch("tempfile.mkstemp", return_value=(mock_fd, str(mock_tmp))), \
             patch("os.fdopen", mock_fdopen), \
             patch("builtins.open", m_open), \
             patch("os.replace") as mock_replace, \
             patch("shutil.copy2"), \
             patch("devsecops_radar.core.remediation._backup_file",
                   return_value=Path("/fake/backup.py")):
            with capture_loguru() as msgs:
                result = apply_patch(finding, "new line\n", base_dir=tmp_path)
            assert result is True
            assert any("Successfully patched" in m for m in msgs)
            mock_tf.writelines.assert_called_once()
            written = mock_tf.writelines.call_args[0][0]
            assert written[1] == "new line\n"

    def test_successful_multiline_patch(self, target_file, finding, tmp_path):
        mock_fd = 123
        mock_tmp = target_file.parent / "tmpfile"
        m_open = mock_open(read_data="line0\nline1\nline2\nline3\n")
        mock_tf = MagicMock()
        mock_fdopen = MagicMock()
        mock_fdopen.return_value.__enter__.return_value = mock_tf

        with patch("tempfile.mkstemp", return_value=(mock_fd, str(mock_tmp))), \
             patch("os.fdopen", mock_fdopen), \
             patch("builtins.open", m_open), \
             patch("os.replace") as mock_replace, \
             patch("shutil.copy2"), \
             patch("devsecops_radar.core.remediation._backup_file",
                   return_value=Path("/fake/backup.py")):
            result = apply_patch(finding, "new line1\nnew line2\n", base_dir=tmp_path)
            assert result is True
            mock_tf.writelines.assert_called_once()
            written = mock_tf.writelines.call_args[0][0]
            # line1 and line2 should be replaced by the two new lines
            assert written[1] == "new line1\n"
            assert written[2] == "new line2\n"

    def test_line_out_of_bounds(self, target_file, tmp_path):
        finding = {"target": str(target_file), "line": 10}
        mock_fd = 123
        mock_tmp = target_file.parent / "tmpfile"
        m_open = mock_open(read_data="line0\nline1\nline2\nline3\n")

        with patch("tempfile.mkstemp", return_value=(mock_fd, str(mock_tmp))), \
             patch("os.fdopen", return_value=MagicMock()), \
             patch("builtins.open", m_open), \
             patch("os.replace") as mock_replace, \
             patch("devsecops_radar.core.remediation._backup_file",
                   return_value=Path("/fake/backup.py")):
            with capture_loguru() as msgs:
                result = apply_patch(finding, "patch", base_dir=tmp_path)
            assert result is False
            assert any("out of bounds" in m for m in msgs)
            mock_replace.assert_not_called()

    def test_patch_failure_rolls_back(self, target_file, finding, tmp_path):
        mock_fd = 123
        mock_tmp = target_file.parent / "tmpfile"
        m_open = mock_open(read_data="line0\nline1\nline2\nline3\n")
        backup = target_file.parent / "backup.py"
        backup.write_text("backup data")

        with patch("tempfile.mkstemp", return_value=(mock_fd, str(mock_tmp))), \
             patch("os.fdopen", return_value=MagicMock()), \
             patch("builtins.open", m_open), \
             patch("os.replace", side_effect=OSError("replace failed")), \
             patch("devsecops_radar.core.remediation._backup_file",
                   return_value=backup), \
             patch("shutil.copy2") as mock_copy:
            with capture_loguru() as msgs:
                result = apply_patch(finding, "newline\n", base_dir=tmp_path)
            assert result is False
            assert any("Failed to apply patch" in m for m in msgs)
            mock_copy.assert_called_with(backup, target_file)


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

    def test_successful_pr_and_push(self):
        """Normal flow: checkout, add, commit, push succeeds."""
        with patch(
            "devsecops_radar.core.remediation.safe_subprocess_run"
        ) as mock_run:
            with capture_loguru() as msgs:
                generate_pr({"a.txt", "b.txt"}, branch="fix-branch")
        # checkout, add a, add b, commit, push = 5 calls
        assert mock_run.call_count == 5
        calls = [call[0][0] for call in mock_run.call_args_list]
        assert calls[0] == ["git", "checkout", "-b", "fix-branch"]
        assert calls[1] == ["git", "add", "a.txt"] or calls[1] == ["git", "add", "b.txt"]
        assert calls[2] == ["git", "add", "a.txt"] or calls[2] == ["git", "add", "b.txt"]
        assert calls[3][:3] == ["git", "commit", "-m"]
        assert calls[4][:4] == ["git", "push", "-u", "origin"]
        assert any("Successfully pushed" in m for m in msgs)

    def test_push_fails_stores_patch_locally(self, backup_and_patch_dirs):
        """When push fails, a format-patch command should be issued."""
        _, fake_patch = backup_and_patch_dirs
        with patch(
            "devsecops_radar.core.remediation.safe_subprocess_run"
        ) as mock_run:
            # Side effect: first 3 calls succeed, 4th (push) raises CalledProcessError, 5th is format-patch
            mock_run.side_effect = [
                None,  # checkout
                None,  # add
                None,  # commit
                subprocess.CalledProcessError(1, "git push"),  # push fails
                None,  # format-patch
            ]
            with capture_loguru() as msgs:
                generate_pr({"a.txt"}, branch="fix-branch")
        # Should have called format-patch as fallback (total 5 calls)
        assert mock_run.call_count == 5
        # Verify format-patch command
        format_patch_call = mock_run.call_args_list[4][0][0]
        assert format_patch_call[0] == "git"
        assert "format-patch" in format_patch_call
        assert str(fake_patch) in format_patch_call

    def test_git_failure(self):
        with patch(
            "devsecops_radar.core.remediation.safe_subprocess_run",
            side_effect=subprocess.CalledProcessError(1, "git", stderr="fatal"),
        ), capture_loguru() as msgs:
            generate_pr({"file.txt"}, branch="fix")
        assert any("Git operation failed" in m for m in msgs)

    def test_git_not_found(self):
        with patch(
            "devsecops_radar.core.remediation.safe_subprocess_run",
            side_effect=FileNotFoundError,
        ), capture_loguru() as msgs:
            generate_pr({"file.txt"}, branch="fix")
        assert any("Git executable not found" in m for m in msgs)