import subprocess
from pathlib import Path
from unittest.mock import call, mock_open, patch

import pytest

from devsecops_radar.core.remediation import (
    BACKUP_DIR,
    _backup_file,
    _init_backup_dir,
    _is_safe_path,
    apply_patch,
    auto_fix,
    generate_pr,
    generate_remediation_guide,
    logger,
)


# ------------------------------------------------------------
# Tests for _init_backup_dir
# ------------------------------------------------------------
class TestInitBackupDir:
    def test_creates_directory_when_not_exists(self, tmp_path):
        test_dir = tmp_path / "new_backup"
        assert not test_dir.exists()
        with patch("devsecops_radar.core.remediation.BACKUP_DIR", test_dir):
            _init_backup_dir()
            assert test_dir.exists()

    def test_does_not_create_if_exists(self, tmp_path):
        test_dir = tmp_path / "existing_backup"
        test_dir.mkdir()
        with patch("devsecops_radar.core.remediation.BACKUP_DIR", test_dir):
            with patch.object(Path, "mkdir") as mock_mkdir:
                _init_backup_dir()
                mock_mkdir.assert_not_called()


# ------------------------------------------------------------
# Tests for _is_safe_path
# ------------------------------------------------------------
class TestIsSafePath:
    def test_safe_path_within_base(self):
        base = Path("/safe")
        target = "/safe/sub/file.txt"
        assert _is_safe_path(target, base) is True

    def test_path_traversal_blocked(self):
        base = Path("/safe")
        assert _is_safe_path("../etc/passwd", base) is False

    def test_absolute_outside_base(self):
        base = Path("/safe")
        assert _is_safe_path("/etc/passwd", base) is False

    def test_resolution_error_logs_and_returns_false(self):
        with patch("pathlib.Path.resolve", side_effect=OSError("bad")), \
             patch.object(logger, "error") as mock_error:
            assert _is_safe_path("anything") is False
            mock_error.assert_called_once()
            assert "Path resolution error" in mock_error.call_args[0][0]

    def test_default_base_cwd(self):
        assert _is_safe_path("src") is True


# ------------------------------------------------------------
# Tests for _backup_file
# ------------------------------------------------------------
class TestBackupFile:
    def test_source_not_exists_returns_none(self):
        with patch.object(Path, "exists", return_value=False):
            assert _backup_file("missing.txt") is None

    def test_successful_backup(self):
        with patch.object(Path, "exists", return_value=True), \
             patch("devsecops_radar.core.remediation.shutil.copy2") as mock_copy, \
             patch("devsecops_radar.core.remediation._init_backup_dir") as mock_init, \
             patch.object(logger, "debug") as mock_debug:
            result = _backup_file("test.txt")
            mock_init.assert_called_once()
            mock_copy.assert_called_once_with(
                Path("test.txt"), BACKUP_DIR / "test.txt.bak"
            )
            assert result == BACKUP_DIR / "test.txt.bak"
            mock_debug.assert_called_once()

    def test_backup_failure_returns_none(self):
        with patch.object(Path, "exists", return_value=True), \
             patch("devsecops_radar.core.remediation.shutil.copy2",
                   side_effect=OSError("disk full")), \
             patch("devsecops_radar.core.remediation._init_backup_dir"), \
             patch.object(logger, "error") as mock_error:
            result = _backup_file("test.txt")
            assert result is None
            mock_error.assert_called_once()
            assert "Backup failed" in mock_error.call_args[0][0]


# ------------------------------------------------------------
# Tests for apply_patch
# ------------------------------------------------------------
class TestApplyPatch:
    @pytest.fixture
    def valid_finding(self):
        return {"target": "src/main.py", "line": 5}

    def test_missing_target_or_line(self):
        finding_no_target = {"line": 5}
        with patch.object(logger, "warning") as mock_warn:
            assert apply_patch(finding_no_target, "patch") is False
            mock_warn.assert_called_with(
                "Finding is missing 'target' or 'line'. Cannot apply patch."
            )

        finding_no_line = {"target": "file.py"}
        with patch.object(logger, "warning") as mock_warn:
            assert apply_patch(finding_no_line, "patch") is False
            mock_warn.assert_called_with(
                "Finding is missing 'target' or 'line'. Cannot apply patch."
            )

    def test_invalid_line_number(self):
        finding = {"target": "file.py", "line": "abc"}
        with patch.object(logger, "error") as mock_error:
            assert apply_patch(finding, "patch") is False
            mock_error.assert_called_with("Invalid line number format: abc")

    def test_unsafe_path(self, valid_finding):
        with patch("devsecops_radar.core.remediation._is_safe_path",
                   return_value=False), \
             patch.object(logger, "error") as mock_error:
            assert apply_patch(valid_finding, "patch") is False
            mock_error.assert_called_with(
                f"Security Error: Target {valid_finding['target']} "
                f"is outside the allowed directory."
            )

    def test_target_file_does_not_exist(self, valid_finding):
        with patch("devsecops_radar.core.remediation._is_safe_path",
                   return_value=True), \
             patch.object(Path, "exists", return_value=False), \
             patch.object(logger, "error") as mock_error:
            assert apply_patch(valid_finding, "patch") is False
            mock_error.assert_called_with(
                f"Target file does not exist: {valid_finding['target']}"
            )

    def test_backup_fails(self, valid_finding):
        with patch("devsecops_radar.core.remediation._is_safe_path",
                   return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch("devsecops_radar.core.remediation._backup_file",
                   return_value=None):
            assert apply_patch(valid_finding, "patch") is False

    def test_line_out_of_bounds(self, valid_finding):
        valid_finding["line"] = 10
        file_lines = ["line1\n", "line2\n", "line3\n", "line4\n", "line5\n"]
        with patch("devsecops_radar.core.remediation._is_safe_path",
                   return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch("devsecops_radar.core.remediation._backup_file",
                   return_value=Path("backup")), \
             patch("builtins.open", mock_open(read_data="".join(file_lines))), \
             patch("os.fdopen", mock_open()), \
             patch("os.replace"), \
             patch("os.close"), \
             patch("os.remove"), \
             patch.object(logger, "error") as mock_error:
            with patch("tempfile.mkstemp", return_value=(7, "tempfile")):
                assert apply_patch(valid_finding, "new line") is False
                mock_error.assert_called_with(
                    f"Line number 10 is out of bounds for "
                    f"{valid_finding['target']}"
                )

    def test_successful_patch(self, valid_finding):
        file_lines = ["line1\n", "line2\n", "line3\n", "line4\n", "line5\n"]
        with patch("devsecops_radar.core.remediation._is_safe_path",
                   return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch("devsecops_radar.core.remediation._backup_file",
                   return_value=Path("backup")), \
             patch("builtins.open", mock_open(read_data="".join(file_lines))), \
             patch("os.fdopen", mock_open()), \
             patch("os.replace") as mock_replace, \
             patch("tempfile.mkstemp", return_value=(7, "tempfile")), \
             patch.object(logger, "info") as mock_info:
            assert apply_patch(valid_finding, "new line") is True
            mock_replace.assert_called_once_with(
                "tempfile", Path(valid_finding["target"])
            )
            mock_info.assert_called_with(
                f"Successfully patched {valid_finding['target']} "
                f"at line {valid_finding['line']}"
            )

    def test_exception_rollback(self, valid_finding):
        file_lines = ["line1\n", "line2\n", "line3\n", "line4\n", "line5\n"]
        backup = Path("backup")
        with patch("devsecops_radar.core.remediation._is_safe_path",
                   return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch("devsecops_radar.core.remediation._backup_file",
                   return_value=backup), \
             patch("builtins.open", mock_open(read_data="".join(file_lines))), \
             patch("os.fdopen", mock_open()), \
             patch("os.replace", side_effect=OSError("replace failed")), \
             patch("tempfile.mkstemp", return_value=(7, "tempfile")), \
             patch.object(logger, "error") as mock_error, \
             patch.object(logger, "info") as mock_info, \
             patch("shutil.copy2") as mock_copy2:
            with patch.object(Path, "exists", return_value=True):
                assert apply_patch(valid_finding, "new line") is False
                mock_error.assert_called_with(
                    f"Failed to apply patch to {valid_finding['target']}: "
                    f"replace failed"
                )
                mock_copy2.assert_called_with(
                    backup, Path(valid_finding["target"])
                )
                mock_info.assert_called_with(
                    f"Rolled back {valid_finding['target']} from backup."
                )


# ------------------------------------------------------------
# Tests for generate_remediation_guide
# ------------------------------------------------------------
class TestGenerateRemediationGuide:
    def test_empty_list(self):
        assert (
            generate_remediation_guide([])
            == "No automated remediations provided by the AI."
        )

    def test_single_remediation_with_steps(self):
        remediations = [
            {
                "finding_id": "F1",
                "title": "Fix XSS",
                "remediation_steps": ["Step 1", "Step 2"],
            }
        ]
        guide = generate_remediation_guide(remediations)
        assert "🛡️  PIPELINE SENTINEL - REMEDIATION GUIDE  🛡️" in guide
        assert "[ID: F1] Fix XSS" in guide
        assert "  1. Step 1" in guide
        assert "  2. Step 2" in guide

    def test_missing_fields(self):
        remediations = [{}]
        guide = generate_remediation_guide(remediations)
        assert "[ID: UNKNOWN] Fix Request" in guide
        assert "  - Manual investigation required." in guide

    def test_mixed_manual_and_auto(self):
        remediations = [
            {"finding_id": "F2", "title": "Fix B", "remediation_steps": []},
        ]
        guide = generate_remediation_guide(remediations)
        assert "[ID: F2] Fix B" in guide
        assert "  - Manual investigation required." in guide


# ------------------------------------------------------------
# Tests for auto_fix
# ------------------------------------------------------------
class TestAutoFix:
    def test_empty_findings(self):
        assert auto_fix([], {}) == set()

    def test_finding_with_matching_remediation_and_patch(self):
        findings = [{"id": "F1", "target": "file.py"}]
        ai_summary = {
            "top_remediations": [
                {"finding_id": "F1", "patch_content": "fixed"}
            ]
        }
        with patch("devsecops_radar.core.remediation.apply_patch",
                   return_value=True):
            result = auto_fix(findings, ai_summary)
            assert result == {"file.py"}

    def test_finding_with_matching_remediation_but_no_patch(self):
        findings = [{"id": "F1", "target": "file.py"}]
        ai_summary = {
            "top_remediations": [
                {"finding_id": "F1"}  # no patch_content
            ]
        }
        with patch(
            "devsecops_radar.core.remediation.apply_patch"
        ) as mock_apply:
            result = auto_fix(findings, ai_summary)
            assert result == set()
            mock_apply.assert_not_called()

    def test_finding_not_in_ai_remediations(self):
        findings = [{"id": "F2", "target": "other.py"}]
        ai_summary = {"top_remediations": []}
        result = auto_fix(findings, ai_summary)
        assert result == set()

    def test_apply_patch_fails(self):
        findings = [{"id": "F1", "target": "file.py"}]
        ai_summary = {
            "top_remediations": [
                {"finding_id": "F1", "patch_content": "bad"}
            ]
        }
        with patch(
            "devsecops_radar.core.remediation.apply_patch",
            return_value=False,
        ):
            result = auto_fix(findings, ai_summary)
            assert result == set()


# ------------------------------------------------------------
# Tests for generate_pr
# ------------------------------------------------------------
class TestGeneratePr:
    def test_no_modified_files(self):
        with patch.object(logger, "info") as mock_info:
            generate_pr(set())
            mock_info.assert_called_with(
                "No files were modified. Skipping PR generation."
            )

    def test_invalid_branch_name(self):
        with patch.object(logger, "error") as mock_error:
            generate_pr({"a.py"}, branch="bad;branch")
            mock_error.assert_called_with(
                "Invalid branch name 'bad;branch'. "
                "Aborting PR generation to prevent command injection."
            )

    def test_valid_flow(self):
        modified = {"a.py", "b.py"}
        with patch(
            "devsecops_radar.core.remediation.subprocess.run"
        ) as mock_run:
            generate_pr(modified)
            calls = mock_run.call_args_list
            assert len(calls) == 5

            # checkout first
            expected_checkout = call(
                ['git', 'checkout', '-b', 'sentinel-auto-fix'],
                check=True, capture_output=True, text=True,
            )
            assert calls[0] == expected_checkout

            # add calls
            add_calls = [c for c in calls if c[0][0][1] == 'add']
            assert len(add_calls) == 2
            files_added = {c[0][0][2] for c in add_calls}
            assert files_added == modified

            # commit
            commit_msg = 'Security Fixes applied by Pipeline Sentinel'
            expected_commit = call(
                ['git', 'commit', '-m', commit_msg],
                check=True, capture_output=True, text=True,
            )
            assert calls[-2] == expected_commit

            # push last
            expected_push = call(
                ['git', 'push', '-u', 'origin', 'sentinel-auto-fix'],
                check=True, capture_output=True, text=True,
            )
            assert calls[-1] == expected_push

    def test_git_called_process_error(self):
        with patch(
            "devsecops_radar.core.remediation.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "git", stderr="error"),
        ), patch.object(logger, "error") as mock_error:
            generate_pr({"a.py"})
            mock_error.assert_called_once()
            assert (
                "Git operation failed during PR generation:"
                in mock_error.call_args[0][0]
            )

    def test_git_not_found(self):
        with patch(
            "devsecops_radar.core.remediation.subprocess.run",
            side_effect=FileNotFoundError,
        ), patch.object(logger, "error") as mock_error:
            generate_pr({"a.py"})
            mock_error.assert_called_with(
                "Git executable not found. Ensure git is installed."
            )
