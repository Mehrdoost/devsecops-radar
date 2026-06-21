"""Tests for the custom rule fusion engine – updated for GPG verification and Rego changes."""

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
# Tests for path security (replaces _is_safe_path)
# ============================================================================
class TestPathSecurity:
    def test_safe_path(self, engine):
        from devsecops_radar.core.path_security import resolve_safe_path
        resolve_safe_path(str(engine.rules_dir / "rules.json"), engine.rules_dir)

    def test_path_outside_rules_dir(self, engine):
        from devsecops_radar.core.path_security import resolve_safe_path
        outside = engine.rules_dir.parent / "malicious.json"
        outside.touch()
        with pytest.raises(ValueError, match="outside"):
            resolve_safe_path(str(outside), engine.rules_dir)

    def test_exception_during_resolve(self, engine):
        with patch.object(Path, "resolve", side_effect=OSError("bad")):
            from devsecops_radar.core.path_security import resolve_safe_path
            with pytest.raises(OSError):
                resolve_safe_path("anything", engine.rules_dir)


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
        with patch("subprocess.run") as mock_run, \
             patch.object(engine, "_verify_gpg_signature", return_value=True):
            engine.update_community_rules()
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "git" in args[0].lower()
            assert "clone" in args

    def test_successful_pull_when_exists(self, engine, monkeypatch):
        monkeypatch.setenv(
            "COMMUNITY_RULES_REPO", "https://github.com/org/repo.git"
        )
        community_dir = engine.rules_dir / "community"
        community_dir.mkdir()
        with patch("subprocess.run") as mock_run, \
             patch.object(engine, "_verify_gpg_signature", return_value=True):
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

    def test_gpg_verification_fails_after_clone(self, engine, monkeypatch, tmp_path):
        """If GPG verification fails, the directory is removed and a critical log appears."""
        monkeypatch.setenv(
            "COMMUNITY_RULES_REPO", "https://github.com/org/repo.git"
        )
        # Let clone succeed, but _verify_gpg_signature returns False
        with patch("subprocess.run") as mock_run, \
             patch.object(engine, "_verify_gpg_signature", return_value=False), \
             patch("shutil.rmtree") as mock_rmtree, \
             capture_loguru() as msgs:
            engine.update_community_rules()
        # clone should have been called
        assert mock_run.call_count == 1
        # rmtree should be called to clean up
        mock_rmtree.assert_called_once()
        assert any("Community rules rejected" in m for m in msgs)


# ============================================================================
# Tests for _load_and_validate_json (unchanged)
# ============================================================================
class TestLoadAndValidateJson:
    def test_valid_rules(self, engine, sample_rule):
        rule_file = engine.rules_dir / "rules.json"
        rule_file.write_text(json.dumps([sample_rule]))
        engine._load_and_validate_json(rule_file)
        assert len(engine.findings) == 1
        assert engine.findings[0]["id"] == "R1"

    def test_dict_wrapped_in_findings(self, engine):
        rule_file = engine.rules_dir / "rules.json"
        rule_file.write_text(
            json.dumps({"findings": [{"id": "X", "target": "a", "severity": "LOW", "title": "t"}]})
        )
        engine._load_and_validate_json(rule_file)
        assert len(engine.findings) == 1

    def test_skip_invalid_items(self, engine):
        rule_file = engine.rules_dir / "rules.json"
        rule_file.write_text(
            json.dumps([
                {"id": "good", "target": "a", "severity": "LOW", "title": "t"},
                {"invalid": "no_id"},
            ])
        )
        engine._load_and_validate_json(rule_file)
        assert len(engine.findings) == 1

    def test_size_limit_exceeded(self, engine):
        engine.max_file_size_bytes = 10
        rule_file = engine.rules_dir / "big.json"
        rule_file.write_text("x" * 100)
        with capture_loguru() as msgs:
            engine._load_and_validate_json(rule_file)
        assert any("exceeds size limit" in m for m in msgs)
        assert len(engine.findings) == 0

    def test_malformed_json(self, engine):
        rule_file = engine.rules_dir / "bad.json"
        rule_file.write_text("not json")
        with capture_loguru() as msgs:
            engine._load_and_validate_json(rule_file)
        assert any("Skipping unsafe path" in m for m in msgs)

    def test_not_a_list(self, engine):
        rule_file = engine.rules_dir / "rules.json"
        rule_file.write_text('"just a string"')
        with capture_loguru() as msgs:
            engine._load_and_validate_json(rule_file)
        assert any("Invalid JSON structure" in m for m in msgs)

    def test_file_not_found(self, engine):
        missing = engine.rules_dir / "missing.json"
        with capture_loguru():
            engine._load_and_validate_json(missing)
        assert len(engine.findings) == 0


# ============================================================================
# Tests for load_all_rules (unchanged)
# ============================================================================
class TestLoadAllRules:
    def test_load_all(self, engine):
        (engine.rules_dir / "rule1.json").write_text(
            json.dumps([{"id": "1", "target": "a", "severity": "LOW", "title": "t"}])
        )
        (engine.rules_dir / "rule2.json").write_text(
            json.dumps([{"id": "2", "target": "b", "severity": "MEDIUM", "title": "t"}])
        )
        (engine.rules_dir / "readme.md").write_text("hello")

        findings = engine.load_all_rules()
        assert len(findings) == 2
        assert engine._loaded is True

        findings2 = engine.load_all_rules()
        assert findings2 == findings

    def test_file_limit(self, engine):
        for i in range(1002):
            (engine.rules_dir / f"rule{i}.json").write_text(
                json.dumps([{"id": str(i), "target": "a", "severity": "LOW", "title": "t"}])
            )
        with capture_loguru() as msgs:
            findings = engine.load_all_rules()
        assert len(findings) == 1001
        assert any("File limit exceeded" in m for m in msgs)

    def test_unsafe_path_skipped(self, engine):
        safe_file = engine.rules_dir / "safe.json"
        safe_file.write_text(
            json.dumps([{"id": "ok", "target": "a", "severity": "LOW", "title": "t"}])
        )
        with patch(
            "devsecops_radar.core.path_security.resolve_safe_path",
            side_effect=ValueError("outside allowed"),
        ):
            with capture_loguru() as msgs:
                findings = engine.load_all_rules()
        assert len(findings) == 0
        assert any("Skipping unsafe path" in m for m in msgs)

    def test_rules_dir_missing(self, tmp_path):
        engine = RuleFusionEngine(rules_dir=str(tmp_path / "nonexistent"))
        assert engine.rules_dir.exists()
        findings = engine.load_all_rules()
        assert findings == []


# ============================================================================
# Tests for evaluate_policy
# ============================================================================
class TestEvaluatePolicy:
    @pytest.fixture(autouse=True)
    def setup_findings(self, engine):
        engine.findings = [
            {"id": "1", "severity": "CRITICAL"},
            {"id": "2", "severity": "CRITICAL"},
            {"id": "3", "severity": "HIGH"},
        ]

    def test_policy_unsafe_path(self, engine, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        policy = tmp_path / "policy.json"
        policy.write_text('{"max_critical": 1}')
        with patch(
            "devsecops_radar.core.path_security.resolve_safe_path",
            side_effect=ValueError("outside allowed"),
        ), capture_loguru():
            result = engine.evaluate_policy(str(policy))
        assert result is True  # skipped, pass by default

    def test_policy_missing_file(self, engine, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        missing = tmp_path / "missing.json"
        with capture_loguru() as msgs:
            result = engine.evaluate_policy(str(missing))
        assert result is True
        assert any("Cannot read policy file" in m for m in msgs)

    def test_policy_missing_threshold(self, engine, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        policy = tmp_path / "policy.json"
        policy.write_text('{"other": 1}')
        with capture_loguru() as msgs:
            result = engine.evaluate_policy(str(policy))
        assert result is True
        assert any("missing 'max_critical' threshold" in m for m in msgs)

    def test_policy_violation_fail_default(self, engine, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        policy = tmp_path / "policy.json"
        policy.write_text('{"max_critical": 1}')
        with capture_loguru() as msgs:
            result = engine.evaluate_policy(str(policy))
        assert result is False
        assert any("Policy Violation!" in m for m in msgs)

    def test_policy_violation_warn(self, engine, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        policy = tmp_path / "policy.json"
        policy.write_text('{"max_critical": 1, "on_violation": "warn"}')
        with capture_loguru() as msgs:
            result = engine.evaluate_policy(str(policy))
        assert result is True
        assert any("Policy warning:" in m for m in msgs)

    def test_policy_pass(self, engine, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        policy = tmp_path / "policy.json"
        policy.write_text('{"max_critical": 3}')
        with capture_loguru() as msgs:
            result = engine.evaluate_policy(str(policy))
        assert result is True
        assert any("Security policy checks passed" in m for m in msgs)

    def test_policy_exception_reading(self, engine, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        policy = tmp_path / "policy.json"
        policy.write_text("not json")
        with capture_loguru():
            result = engine.evaluate_policy(str(policy))
        assert result is True  # pass by default
