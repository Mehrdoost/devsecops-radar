import json
import os
import subprocess
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest
from pydantic import ValidationError

from devsecops_radar.core.rule_fusion import (
    CustomRuleSchema,
    RuleFusionEngine,
    logger,
)


# ------------------------------------------------------------
# Tests for CustomRuleSchema
# ------------------------------------------------------------
class TestCustomRuleSchema:
    def test_valid_minimal(self):
        rule = CustomRuleSchema(
            id="R1",
            target="src/app.py",
            severity="HIGH",
            title="SQL Injection",
        )
        assert rule.tool == "Custom Rule"
        assert rule.description == ""

    def test_valid_full(self):
        rule = CustomRuleSchema(
            id="R2",
            tool="Semgrep",
            target="file.js",
            severity="CRITICAL",
            title="XSS",
            description="A cross-site scripting vulnerability",
        )
        assert rule.tool == "Semgrep"
        assert rule.description == "A cross-site scripting vulnerability"

    def test_missing_required_raises(self):
        with pytest.raises(ValidationError):
            CustomRuleSchema(target="x", severity="LOW")  # missing id, title


# ------------------------------------------------------------
# Tests for RuleFusionEngine initialization
# ------------------------------------------------------------
class TestRuleFusionEngineInit:
    def test_defaults(self, tmp_path):
        non_existent_dir = tmp_path / "new_rules"  # does not exist yet
        with patch.object(logger, "info") as mock_info:
            engine = RuleFusionEngine(rules_dir=str(non_existent_dir))
            assert engine.max_file_size_bytes == 10 * 1024 * 1024
            assert non_existent_dir.exists()  # mkdir was called
            mock_info.assert_not_called()  # no info logs

    def test_custom_max_size(self, tmp_path):
        engine = RuleFusionEngine(rules_dir=str(tmp_path), max_file_size_mb=5)
        assert engine.max_file_size_bytes == 5 * 1024 * 1024

    def test_directory_already_exists(self, tmp_path):
        dir_path = tmp_path / "rules"
        dir_path.mkdir()
        with patch("devsecops_radar.core.rule_fusion.Path.mkdir") as mock_mkdir:
            RuleFusionEngine(rules_dir=str(dir_path))
            mock_mkdir.assert_not_called()


# ------------------------------------------------------------
# Tests for _is_safe_path
# ------------------------------------------------------------
class TestIsSafePath:
    def setup_method(self):
        self.rules_dir = Path("/safe/rules")
        self.engine = RuleFusionEngine.__new__(RuleFusionEngine)
        self.engine.rules_dir = self.rules_dir

    def test_relative_to_rules_dir(self):
        with patch.object(Path, "resolve") as mock_resolve:
            mock_resolve.return_value = self.rules_dir / "file.json"
            assert self.engine._is_safe_path(Path("file.json")) is True

    def test_parent_traversal_blocked(self):
        with patch.object(Path, "resolve") as mock_resolve:
            mock_resolve.return_value = self.rules_dir.parent / "etc" / "passwd"
            assert self.engine._is_safe_path(Path("../etc/passwd")) is False

    def test_resolution_error(self):
        with patch.object(Path, "resolve", side_effect=OSError("bad")), \
             patch.object(logger, "error") as mock_log:
            assert self.engine._is_safe_path(Path("bad")) is False
            mock_log.assert_called_once()
            assert "Path resolution error" in mock_log.call_args[0][0]


# ------------------------------------------------------------
# Tests for update_community_rules
# ------------------------------------------------------------
class TestUpdateCommunityRules:
    @pytest.fixture
    def engine(self, tmp_path):
        return RuleFusionEngine(rules_dir=str(tmp_path / "rules"))

    def test_no_repo_configured(self, engine):
        with patch.dict(os.environ, {}, clear=True), patch.object(logger, "info") as mock_log:
            engine.update_community_rules()
            mock_log.assert_called_with("No community repository configured. Skipping update.")

    def test_invalid_url_scheme(self, engine):
        with patch.dict(os.environ, {"COMMUNITY_RULES_REPO": "http://github.com/test.git"}), \
             patch.object(logger, "error") as mock_log:
            engine.update_community_rules()
            mock_log.assert_called_with(
                "Security Error: Community repo must be a valid https://github.com URL."
            )

    def test_invalid_host(self, engine):
        with patch.dict(os.environ, {"COMMUNITY_RULES_REPO": "https://evil.com/test.git"}), \
             patch.object(logger, "error") as mock_log:
            engine.update_community_rules()
            mock_log.assert_called()

    def test_invalid_characters_in_url(self, engine):
        with patch.dict(os.environ, {"COMMUNITY_RULES_REPO": "https://github.com/test;rm.git"}), \
             patch.object(logger, "error") as mock_log:
            engine.update_community_rules()
            mock_log.assert_called()

    def test_valid_url_clone_success(self, engine):
        repo = "https://github.com/example/rules.git"
        # Do NOT create community dir, so clone branch is taken
        with patch.dict(os.environ, {"COMMUNITY_RULES_REPO": repo}), \
             patch("devsecops_radar.core.rule_fusion.subprocess.run") as mock_run, \
             patch.object(logger, "info") as mock_log:
            engine.update_community_rules()
            target_dir = engine.rules_dir / "community"
            mock_run.assert_called_with(
                ["git", "clone", "--depth", "1", repo, str(target_dir)],
                check=True, capture_output=True, timeout=60,
            )
            mock_log.assert_called_with(f"Cloning community rules from {repo}...")

    def test_valid_url_pull_existing(self, engine):
        repo = "https://github.com/example/rules.git"
        # Create the community directory to trigger pull branch
        community_dir = engine.rules_dir / "community"
        community_dir.mkdir(parents=True)
        with patch.dict(os.environ, {"COMMUNITY_RULES_REPO": repo}), \
             patch("devsecops_radar.core.rule_fusion.subprocess.run") as mock_run, \
             patch.object(logger, "info") as mock_log:
            engine.update_community_rules()
            mock_run.assert_called_with(
                ["git", "-C", str(community_dir), "pull", "origin", "main"],
                check=True, capture_output=True, timeout=30,
            )
            mock_log.assert_called_with("Updating existing community rules...")

    def test_git_timeout(self, engine):
        with patch.dict(os.environ, {"COMMUNITY_RULES_REPO": "https://github.com/example/rules.git"}), \
             patch("devsecops_radar.core.rule_fusion.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("git", 60)), \
             patch.object(logger, "error") as mock_log:
            engine.update_community_rules()
            mock_log.assert_called_with("Git operation timed out.")

    def test_git_called_process_error(self, engine):
        with patch.dict(os.environ, {"COMMUNITY_RULES_REPO": "https://github.com/example/rules.git"}), \
             patch("devsecops_radar.core.rule_fusion.subprocess.run",
                   side_effect=subprocess.CalledProcessError(1, "git",
                                                             stderr=b"some error")), \
             patch.object(logger, "error") as mock_log:
            engine.update_community_rules()
            mock_log.assert_called_with("Git operation failed: some error")

    def test_git_unexpected_exception(self, engine):
        with patch.dict(os.environ, {"COMMUNITY_RULES_REPO": "https://github.com/example/rules.git"}), \
             patch("devsecops_radar.core.rule_fusion.subprocess.run",
                   side_effect=OSError("disk full")), \
             patch.object(logger, "error") as mock_log:
            engine.update_community_rules()
            mock_log.assert_called_with("Unexpected error during community rules update: disk full")


# ------------------------------------------------------------
# Tests for _load_and_validate_json
# ------------------------------------------------------------
class TestLoadAndValidateJson:
    @pytest.fixture
    def engine(self, tmp_path):
        eng = RuleFusionEngine(rules_dir=str(tmp_path / "rules"))
        return eng

    def test_file_not_found(self, engine):
        with patch.object(Path, "is_file", return_value=False):
            engine._load_and_validate_json(Path("missing.json"))
            assert engine.findings == []

    def test_file_exceeds_size_limit(self, engine):
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "stat") as mock_stat, \
             patch.object(logger, "warning") as mock_log:
            mock_stat.return_value.st_size = engine.max_file_size_bytes + 1
            engine._load_and_validate_json(Path("large.json"))
            mock_log.assert_called_with("File large.json exceeds size limit. Skipping.")
            assert engine.findings == []

    def test_valid_json_single_object(self, engine):
        rule = {"id": "R1", "target": "test.py", "severity": "HIGH", "title": "Test"}
        json_data = json.dumps(rule)
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "stat") as mock_stat, \
             patch("builtins.open", mock_open(read_data=json_data)), \
             patch.object(logger, "info") as mock_log:
            mock_stat.return_value.st_size = 100
            engine._load_and_validate_json(Path("rule.json"))
            assert len(engine.findings) == 1
            assert engine.findings[0]["id"] == "R1"
            mock_log.assert_called_with("Loaded 1 valid custom rules from rule.json")

    def test_json_list_of_rules(self, engine):
        rules = [
            {"id": "A", "target": "a.py", "severity": "CRITICAL", "title": "A"},
            {"id": "B", "target": "b.py", "severity": "LOW", "title": "B", "description": "desc"},
        ]
        json_data = json.dumps(rules)
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "stat") as mock_stat, \
             patch("builtins.open", mock_open(read_data=json_data)), \
             patch.object(logger, "info") as mock_log:
            mock_stat.return_value.st_size = 100
            engine._load_and_validate_json(Path("rules.json"))
            assert len(engine.findings) == 2
            mock_log.assert_called_with("Loaded 2 valid custom rules from rules.json")

    def test_dict_with_findings_key(self, engine):
        data = {"findings": [{"id": "F1", "target": "f.py", "severity": "MEDIUM", "title": "F"}]}
        json_data = json.dumps(data)
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "stat") as mock_stat, \
             patch("builtins.open", mock_open(read_data=json_data)):
            mock_stat.return_value.st_size = 100
            engine._load_and_validate_json(Path("dict.json"))
            assert len(engine.findings) == 1
            assert engine.findings[0]["id"] == "F1"

    def test_dict_without_list_converts_to_list(self, engine):
        # dict without "findings" or "results" -> normalized to [dict]
        data = {"id": "X"}  # incomplete, validation will fail
        json_data = json.dumps(data)
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "stat") as mock_stat, \
             patch("builtins.open", mock_open(read_data=json_data)), \
             patch.object(logger, "debug") as mock_debug:
            mock_stat.return_value.st_size = 100
            engine._load_and_validate_json(Path("obj.json"))
            # The single dict is invalid, so it is skipped with a debug message
            mock_debug.assert_called_once()
            assert engine.findings == []

    def test_invalid_json_malformed(self, engine):
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "stat") as mock_stat, \
             patch("builtins.open", mock_open(read_data="{bad")), \
             patch.object(logger, "error") as mock_log:
            mock_stat.return_value.st_size = 100
            engine._load_and_validate_json(Path("bad.json"))
            mock_log.assert_called_with("Malformed JSON in bad.json. Skipping.")

    def test_general_exception(self, engine):
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "stat") as mock_stat, \
             patch("builtins.open", side_effect=PermissionError("denied")), \
             patch.object(logger, "error") as mock_log:
            mock_stat.return_value.st_size = 100
            engine._load_and_validate_json(Path("nope.json"))
            mock_log.assert_called_with("Error processing nope.json: denied")

    def test_mixed_valid_invalid_objects(self, engine):
        items = [
            {"id": "OK", "target": "ok.py", "severity": "LOW", "title": "ok"},
            "not a dict",  # skipped without debug
            {"target": "missing_id"},  # invalid, will produce one debug
        ]
        json_data = json.dumps(items)
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "stat") as mock_stat, \
             patch("builtins.open", mock_open(read_data=json_data)), \
             patch.object(logger, "debug") as mock_debug:
            mock_stat.return_value.st_size = 100
            engine._load_and_validate_json(Path("mixed.json"))
            assert len(engine.findings) == 1
            assert engine.findings[0]["id"] == "OK"
            # Only the invalid dict triggers debug; string is silently skipped
            mock_debug.assert_called_once()


# ------------------------------------------------------------
# Tests for load_all_rules
# ------------------------------------------------------------
class TestLoadAllRules:
    @pytest.fixture
    def engine(self, tmp_path):
        return RuleFusionEngine(rules_dir=str(tmp_path / "rules"))

    def test_directory_not_exists(self, engine):
        with patch.object(Path, "exists", return_value=False):
            result = engine.load_all_rules()
            assert result == engine.findings
            assert result == []

    def test_file_limit_exceeded(self, engine):
        # 1002 files -> 1001 processed before break (file_count starts at 0, after 1001 increments >1000 triggers break)
        mock_files = [Path(f"file{i}.json") for i in range(1002)]
        with patch.object(Path, "rglob", return_value=mock_files), \
             patch.object(engine, "_is_safe_path", return_value=True), \
             patch.object(engine, "_load_and_validate_json") as mock_load, \
             patch.object(logger, "warning") as mock_warn:
            result = engine.load_all_rules()
            # 1001 files processed, then break
            assert mock_load.call_count == 1001
            mock_warn.assert_called_with(
                "File limit exceeded (1000). Stopping rule loading to prevent memory exhaustion."
            )
            assert result == engine.findings

    def test_unsafe_path_skipped(self, engine):
        safe_path = Path("safe.json")
        unsafe_path = Path("../unsafe.json")
        mock_files = [safe_path, unsafe_path]
        with patch.object(Path, "rglob", return_value=mock_files), \
             patch.object(engine, "_is_safe_path", side_effect=[True, False]), \
             patch.object(engine, "_load_and_validate_json") as mock_load, \
             patch.object(logger, "warning") as mock_warn:
            engine.load_all_rules()
            assert mock_load.call_count == 1
            mock_warn.assert_called_once()
            warning_msg = mock_warn.call_args[0][0]
            assert "Skipping unsafe path:" in warning_msg
            # The path string depends on OS; just check it contains the filename
            assert "unsafe.json" in warning_msg

    def test_normal_loading(self, engine):
        mock_files = [Path("a.json"), Path("b.json")]
        with patch.object(Path, "rglob", return_value=mock_files), \
             patch.object(engine, "_is_safe_path", return_value=True), \
             patch.object(engine, "_load_and_validate_json") as mock_load:
            result = engine.load_all_rules()
            assert mock_load.call_count == 2
            assert result is engine.findings


# ------------------------------------------------------------
# Tests for evaluate_policy
# ------------------------------------------------------------
class TestEvaluatePolicy:
    @pytest.fixture
    def engine(self, tmp_path):
        eng = RuleFusionEngine(rules_dir=str(tmp_path / "rules"))
        # add some findings
        eng.findings = [
            {"severity": "CRITICAL", "id": "C1"},
            {"severity": "HIGH", "id": "H1"},
            {"severity": "CRITICAL", "id": "C2"},
        ]
        return eng

    def test_policy_path_unsafe(self, engine):
        with patch.object(engine, "_is_safe_path", return_value=False), \
             patch.object(logger, "warning") as mock_log:
            result = engine.evaluate_policy("unsafe.json")
            assert result is True
            mock_log.assert_called_with(
                "Policy file not found or unsafe: unsafe.json. Policy evaluation skipped."
            )

    def test_policy_file_not_exist(self, engine):
        with patch.object(engine, "_is_safe_path", return_value=True), \
             patch.object(Path, "exists", return_value=False), \
             patch.object(logger, "warning") as mock_log:
            result = engine.evaluate_policy("nonexistent.json")
            assert result is True
            mock_log.assert_called()

    def test_missing_max_critical(self, engine):
        policy_data = json.dumps({})
        with patch.object(engine, "_is_safe_path", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=policy_data)), \
             patch.object(logger, "warning") as mock_log:
            result = engine.evaluate_policy("policy.json")
            assert result is True
            mock_log.assert_called_with(
                "Policy file missing 'max_critical' threshold. Passing by default."
            )

    def test_compliant_policy(self, engine):
        policy_data = json.dumps({"max_critical": 5})
        with patch.object(engine, "_is_safe_path", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=policy_data)), \
             patch.object(logger, "info") as mock_log:
            result = engine.evaluate_policy("policy.json")
            assert result is True
            mock_log.assert_called_with("Security policy checks passed.")

    def test_violation_policy(self, engine):
        policy_data = json.dumps({"max_critical": 1})  # we have 2 criticals
        with patch.object(engine, "_is_safe_path", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=policy_data)), \
             patch.object(logger, "error") as mock_log:
            result = engine.evaluate_policy("policy.json")
            assert result is False
            mock_log.assert_called_with(
                "Policy Violation! Found 2 CRITICAL issues (Max allowed: 1)."
            )

    def test_policy_json_decode_error(self, engine):
        with patch.object(engine, "_is_safe_path", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="{bad")), \
             patch.object(logger, "error") as mock_log:
            result = engine.evaluate_policy("malformed.json")
            assert result is False
            mock_log.assert_called_once()
            assert "Policy evaluation failed" in mock_log.call_args[0][0]

    def test_policy_generic_exception(self, engine):
        with patch.object(engine, "_is_safe_path", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch("builtins.open", side_effect=OSError("io error")), \
             patch.object(logger, "error") as mock_log:
            result = engine.evaluate_policy("error.json")
            assert result is False
            mock_log.assert_called()
