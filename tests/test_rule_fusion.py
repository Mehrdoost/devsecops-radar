"""Tests for the custom rule fusion engine."""

import json
import subprocess
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
from loguru import logger

from devsecops_radar.core.rule_fusion import RuleFusionEngine


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
def engine(tmp_path):
    """Create a RuleFusionEngine with a temporary rules directory."""
    rules_dir = tmp_path / "custom_rules"
    return RuleFusionEngine(rules_dir=str(rules_dir))


@pytest.fixture
def sample_rule():
    return {
        "id": "R1",
        "tool": "my-tool",
        "target": "/app/main.py",
        "severity": "HIGH",
        "title": "SQL Injection",
        "description": "Found SQLi",
    }


# ============================================================================
# Tests for _is_safe_path
# ============================================================================
class TestIsSafePath:
    def test_safe_path(self, engine):
        safe = engine.rules_dir / "rules.json"
        assert engine._is_safe_path(safe) is True

    def test_path_outside_rules_dir(self, tmp_path):
        engine = RuleFusionEngine(rules_dir=str(tmp_path / "rules"))
        outside = tmp_path / "malicious.json"
        outside.touch()
        assert engine._is_safe_path(outside) is False

    def test_exception_during_resolve(self, engine):
        with patch.object(Path, "resolve", side_effect=OSError("bad")):
            assert engine._is_safe_path(Path("anything")) is False


# ============================================================================
# Tests for update_community_rules
# ============================================================================
class TestUpdateCommunityRules:
    @pytest.fixture(autouse=True)
    def clean_env(self, monkeypatch):
        monkeypatch.delenv("COMMUNITY_RULES_REPO", raising=False)

    def test_no_repo_configured(self, engine):
        with capture_loguru() as msgs:
            engine.update_community_rules()
        assert any("No community repository" in m for m in msgs)

    def test_invalid_scheme(self, engine, monkeypatch):
        monkeypatch.setenv("COMMUNITY_RULES_REPO", "http://github.com/org/repo.git")
        with capture_loguru() as msgs:
            engine.update_community_rules()
        assert any("must be a valid https://github.com URL" in m for m in msgs)

    def test_non_github_host(self, engine, monkeypatch):
        monkeypatch.setenv("COMMUNITY_RULES_REPO", "https://evil.com/org/repo.git")
        with capture_loguru() as msgs:
            engine.update_community_rules()
        assert any("must be a valid https://github.com URL" in m for m in msgs)

    def test_invalid_characters_in_url(self, engine, monkeypatch):
        monkeypatch.setenv(
            "COMMUNITY_RULES_REPO", "https://github.com/org/repo.git;ls"
        )
        with capture_loguru() as msgs:
            engine.update_community_rules()
        assert any("Invalid characters in repo URL" in m for m in msgs)

    def test_successful_clone(self, engine, monkeypatch):
        monkeypatch.setenv(
            "COMMUNITY_RULES_REPO", "https://github.com/org/repo.git"
        )
        with patch("subprocess.run") as mock_run:
            engine.update_community_rules()
            # since target_dir doesn't exist, it should clone
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args[0] == "git"
            assert "clone" in args

    def test_successful_pull_when_exists(self, engine, monkeypatch):
        monkeypatch.setenv(
            "COMMUNITY_RULES_REPO", "https://github.com/org/repo.git"
        )
        community_dir = engine.rules_dir / "community"
        community_dir.mkdir()
        with patch("subprocess.run") as mock_run:
            engine.update_community_rules()
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "pull" in args

    def test_git_timeout(self, engine, monkeypatch):
        monkeypatch.setenv(
            "COMMUNITY_RULES_REPO", "https://github.com/org/repo.git"
        )
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("git", 30)
        ), capture_loguru() as msgs:
            engine.update_community_rules()
        assert any("Git operation timed out" in m for m in msgs)

    def test_git_called_process_error(self, engine, monkeypatch):
        monkeypatch.setenv(
            "COMMUNITY_RULES_REPO", "https://github.com/org/repo.git"
        )
        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(
                1, "git", stderr=b"some error"
            ),
        ), capture_loguru() as msgs:
            engine.update_community_rules()
        assert any("Git operation failed" in m for m in msgs)

    def test_unexpected_exception(self, engine, monkeypatch):
        monkeypatch.setenv(
            "COMMUNITY_RULES_REPO", "https://github.com/org/repo.git"
        )
        with patch(
            "subprocess.run", side_effect=Exception("unexpected")
        ), capture_loguru() as msgs:
            engine.update_community_rules()
        assert any("Unexpected error during community rules update" in m for m in msgs)


# ============================================================================
# Tests for _load_and_validate_json
# ============================================================================
class TestLoadAndValidateJson:
    def test_valid_rules(self, engine, sample_rule, tmp_path):
        rule_file = tmp_path / "rules.json"
        rule_file.write_text(json.dumps([sample_rule]))
        engine._load_and_validate_json(rule_file)
        assert len(engine.findings) == 1
        assert engine.findings[0]["id"] == "R1"

    def test_dict_wrapped_in_findings(self, engine, tmp_path):
        rule_file = tmp_path / "rules.json"
        rule_file.write_text(
            json.dumps({"findings": [{"id": "X", "target": "a", "severity": "LOW", "title": "t"}]})
        )
        engine._load_and_validate_json(rule_file)
        assert len(engine.findings) == 1

    def test_skip_invalid_items(self, engine, tmp_path):
        rule_file = tmp_path / "rules.json"
        rule_file.write_text(
            json.dumps([
                {"id": "good", "target": "a", "severity": "LOW", "title": "t"},
                {"invalid": "no_id"},
            ])
        )
        engine._load_and_validate_json(rule_file)
        assert len(engine.findings) == 1

    def test_size_limit_exceeded(self, engine, tmp_path):
        engine.max_file_size_bytes = 10
        rule_file = tmp_path / "big.json"
        rule_file.write_text("x" * 100)
        with capture_loguru() as msgs:
            engine._load_and_validate_json(rule_file)
        assert any("exceeds size limit" in m for m in msgs)
        assert len(engine.findings) == 0

    def test_malformed_json(self, engine, tmp_path):
        rule_file = tmp_path / "bad.json"
        rule_file.write_text("not json")
        with capture_loguru() as msgs:
            engine._load_and_validate_json(rule_file)
        assert any("Malformed JSON" in m for m in msgs)

    def test_not_a_list(self, engine, tmp_path):
        rule_file = tmp_path / "rules.json"
        rule_file.write_text('"just a string"')
        with capture_loguru() as msgs:
            engine._load_and_validate_json(rule_file)
        assert any("Invalid JSON structure" in m for m in msgs)

    def test_file_not_found(self, engine, tmp_path):
        missing = tmp_path / "missing.json"
        with capture_loguru():
            engine._load_and_validate_json(missing)
        # No error expected, just returns
        assert len(engine.findings) == 0


# ============================================================================
# Tests for load_all_rules
# ============================================================================
class TestLoadAllRules:
    def test_load_all(self, engine, tmp_path):
        # Create a few JSON files inside the rules directory
        (engine.rules_dir / "rule1.json").write_text(
            json.dumps([{"id": "1", "target": "a", "severity": "LOW", "title": "t"}])
        )
        (engine.rules_dir / "rule2.json").write_text(
            json.dumps([{"id": "2", "target": "b", "severity": "MEDIUM", "title": "t"}])
        )
        # Create a non-json file, should be ignored
        (engine.rules_dir / "readme.md").write_text("hello")
        # Create a file outside rules dir via symlink? Not needed.

        findings = engine.load_all_rules()
        assert len(findings) == 2
        assert engine._loaded is True

        # Second call should return same findings without reloading
        findings2 = engine.load_all_rules()
        assert findings2 == findings

    def test_file_limit(self, engine, tmp_path):
        # Create many files to trigger the warning and limit.
        # The engine loads 1001 files before breaking on the 1002nd iteration.
        for i in range(1002):   # 0 … 1001 => 1002 files
            (engine.rules_dir / f"rule{i}.json").write_text(
                json.dumps([{"id": str(i), "target": "a", "severity": "LOW", "title": "t"}])
            )
        with capture_loguru() as msgs:
            findings = engine.load_all_rules()
        # Loads 1001 findings (first 1000 + the extra one before the break check)
        assert len(findings) == 1001
        assert any("File limit exceeded" in m for m in msgs)

    def test_unsafe_path_skipped(self, engine, tmp_path):
        safe_file = engine.rules_dir / "safe.json"
        safe_file.write_text(
            json.dumps([{"id": "ok", "target": "a", "severity": "LOW", "title": "t"}])
        )
        # Mock _is_safe_path to return False for a specific file
        original = engine._is_safe_path

        def mock_is_safe(path, base_dir=None):
            if path.name == "safe.json":
                return False
            return original(path, base_dir)

        with patch.object(engine, "_is_safe_path", side_effect=mock_is_safe):
            with capture_loguru() as msgs:
                findings = engine.load_all_rules()
        # The safe.json should be skipped, so no findings
        assert len(findings) == 0
        assert any("Skipping unsafe path" in m for m in msgs)

    def test_rules_dir_missing(self, tmp_path):
        engine = RuleFusionEngine(rules_dir=str(tmp_path / "nonexistent"))
        # Directory should be created automatically in __init__
        assert engine.rules_dir.exists()
        findings = engine.load_all_rules()
        assert findings == []


# ============================================================================
# Tests for evaluate_policy
# ============================================================================
class TestEvaluatePolicy:
    @pytest.fixture(autouse=True)
    def setup_findings(self, engine):
        # Pre-populate some findings for policy checks
        engine.findings = [
            {"id": "1", "severity": "CRITICAL"},
            {"id": "2", "severity": "CRITICAL"},
            {"id": "3", "severity": "HIGH"},
        ]

    def test_policy_unsafe_path(self, engine, tmp_path):
        policy = tmp_path / "policy.json"
        policy.write_text('{"max_critical": 1}')
        with patch.object(
            engine, "_is_safe_path", return_value=False
        ), capture_loguru() as msgs:
            result = engine.evaluate_policy(str(policy))
        assert result is True  # skipped, pass by default
        assert any("outside the allowed base directory" in m for m in msgs)

    def test_policy_missing_file(self, engine, tmp_path):
        missing = tmp_path / "missing.json"
        # Make the path safe so we can reach the existence check
        with patch.object(engine, "_is_safe_path", return_value=True):
            with capture_loguru() as msgs:
                result = engine.evaluate_policy(str(missing))
        assert result is True
        assert any("Policy file not found" in m for m in msgs)

    def test_policy_missing_threshold(self, engine, tmp_path):
        policy = tmp_path / "policy.json"
        policy.write_text('{"other": 1}')
        with patch.object(
            engine, "_is_safe_path", return_value=True
        ), capture_loguru() as msgs:
            result = engine.evaluate_policy(str(policy))
        assert result is True
        assert any("missing 'max_critical' threshold" in m for m in msgs)

    def test_policy_violation_fail_default(self, engine, tmp_path):
        policy = tmp_path / "policy.json"
        policy.write_text('{"max_critical": 1}')
        with patch.object(engine, "_is_safe_path", return_value=True), capture_loguru() as msgs:
            result = engine.evaluate_policy(str(policy))
        assert result is False
        assert any("Policy Violation!" in m for m in msgs)

    def test_policy_violation_warn(self, engine, tmp_path):
        policy = tmp_path / "policy.json"
        policy.write_text('{"max_critical": 1, "on_violation": "warn"}')
        with patch.object(engine, "_is_safe_path", return_value=True), capture_loguru() as msgs:
            result = engine.evaluate_policy(str(policy))
        assert result is True
        assert any("Policy warning:" in m for m in msgs)

    def test_policy_pass(self, engine, tmp_path):
        policy = tmp_path / "policy.json"
        policy.write_text('{"max_critical": 3}')
        with patch.object(engine, "_is_safe_path", return_value=True), capture_loguru() as msgs:
            result = engine.evaluate_policy(str(policy))
        assert result is True
        assert any("Security policy checks passed" in m for m in msgs)

    def test_policy_exception_reading(self, engine, tmp_path):
        policy = tmp_path / "policy.json"
        policy.write_text("not json")
        with patch.object(engine, "_is_safe_path", return_value=True), capture_loguru() as msgs:
            result = engine.evaluate_policy(str(policy))
        assert result is False
        assert any("Policy evaluation failed" in m for m in msgs)
