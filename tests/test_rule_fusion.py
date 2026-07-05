"""Tests for the RuleFusion engine – custom rules loading, validation,
community rules update, and policy evaluation.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from devsecops_radar.core.rule_fusion import RuleFusionEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def engine(tmp_path: Path) -> RuleFusionEngine:
    """Return an engine pointed at a temporary rules directory."""
    base = tmp_path / "base"
    base.mkdir()
    return RuleFusionEngine(rules_dir="custom_rules", base_dir=base)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _write_rule(rules_dir: Path, name: str, rules: list[dict]) -> Path:
    """Write a JSON rule file and return its path."""
    rules_dir.mkdir(parents=True, exist_ok=True)
    f = rules_dir / name
    f.write_text(json.dumps(rules), encoding="utf-8")
    return f


# ---------------------------------------------------------------------------
# Path security tests
# ---------------------------------------------------------------------------
class TestPathSecurity:
    def test_path_outside_rules_dir(
        self, engine: RuleFusionEngine, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A file outside base_dir triggers a warning and is skipped."""
        outside = Path("/etc/passwd") if Path("/etc/passwd").exists() else Path(
            "C:/Windows/System32/drivers/etc/hosts"
        )
        if not outside.exists():
            pytest.skip("No suitable outside path for test.")
        with caplog.at_level(logging.WARNING):
            engine._load_and_validate_json(outside)
        assert any("unsafe path" in record.message.lower() for record in caplog.records)

    def test_exception_during_resolve(
        self, engine: RuleFusionEngine, caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulate an exception during resolve_safe_path; warning is logged."""
        monkeypatch.setattr(
            "devsecops_radar.core.rule_fusion.resolve_safe_path",
            MagicMock(side_effect=OSError("mock error")),
        )
        dummy = engine.rules_dir / "dummy.json"
        with caplog.at_level(logging.WARNING):
            engine._load_and_validate_json(dummy)
        assert any(
            "unsafe path" in record.message.lower() or "error" in record.message.lower()
            for record in caplog.records
        )


# ---------------------------------------------------------------------------
# Community rules update tests
# ---------------------------------------------------------------------------
class TestUpdateCommunityRules:
    def test_invalid_characters_in_url(
        self, engine: RuleFusionEngine, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture
    ) -> None:
        """URL with invalid characters is rejected early."""
        monkeypatch.setenv("COMMUNITY_RULES_REPO", "https://example.com/repo;evil")
        with caplog.at_level(logging.ERROR):
            engine.update_community_rules()
        assert any("must end with .git" in record.message for record in caplog.records)

    def test_missing_git_suffix(
        self, engine: RuleFusionEngine, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("COMMUNITY_RULES_REPO", "https://github.com/user/repo")
        with caplog.at_level(logging.ERROR):
            engine.update_community_rules()
        assert any("must end with .git" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# JSON loading / validation
# ---------------------------------------------------------------------------
class TestLoadAndValidateJson:
    def test_malformed_json(
        self, engine: RuleFusionEngine, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Invalid JSON logs a warning about unsafe path and is skipped."""
        f = _write_rule(engine.rules_dir, "bad.json", [])
        f.write_text("not json")
        with caplog.at_level(logging.WARNING):
            engine._load_and_validate_json(f)
        assert any("unsafe path" in record.message.lower() for record in caplog.records)

    def test_not_a_list(
        self, engine: RuleFusionEngine, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A JSON object that is not a list triggers a warning."""
        f = _write_rule(engine.rules_dir, "object.json", [])
        f.write_text(json.dumps({"findings": "not a list"}))
        with caplog.at_level(logging.WARNING):
            engine._load_and_validate_json(f)
        assert any("Expected a list" in record.message for record in caplog.records)

    def test_valid_rules_are_loaded(self, engine: RuleFusionEngine) -> None:
        """Well‑formed rules are loaded into the engine."""
        _write_rule(
            engine.rules_dir,
            "valid.json",
            [{"id": "R1", "target": "/x", "severity": "LOW", "title": "Test"}],
        )
        findings = engine.load_all_rules()
        assert len(findings) == 1
        assert findings[0]["id"] == "R1"


# ---------------------------------------------------------------------------
# load_all_rules limits
# ---------------------------------------------------------------------------
class TestLoadAllRules:
    def test_file_limit(self, engine: RuleFusionEngine) -> None:
        """Only 1001 files are processed; the rest are skipped."""
        rules_dir = engine.rules_dir
        rules_dir.mkdir(parents=True, exist_ok=True)
        for i in range(1002):
            _write_rule(rules_dir, f"rule_{i}.json",
                        [{"id": f"R{i}", "target": "/x", "severity": "LOW", "title": "T"}])
        findings = engine.load_all_rules()
        assert len(findings) == 1001


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------
class TestEvaluatePolicy:
    def test_policy_violation_fails(
        self, engine: RuleFusionEngine, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Fails when critical findings exceed max_critical."""
        _write_rule(
            engine.rules_dir, "crit.json",
            [{"id": "C1", "severity": "CRITICAL", "title": "Crit", "target": "/"}]
        )
        engine.load_all_rules()
        policy = engine.rules_dir / "policy.json"
        policy.write_text(json.dumps({"max_critical": 0}))
        with caplog.at_level(logging.ERROR):
            result = engine.evaluate_policy(str(policy))
        assert result is False
        assert any("Policy Violation" in record.message for record in caplog.records)

    def test_policy_passes_when_under_limit(self, engine: RuleFusionEngine) -> None:
        """Passes when critical findings are within threshold."""
        _write_rule(
            engine.rules_dir, "low.json",
            [{"id": "L1", "severity": "LOW", "title": "Low", "target": "/"}]
        )
        engine.load_all_rules()
        policy = engine.rules_dir / "policy.json"
        policy.write_text(json.dumps({"max_critical": 1}))
        result = engine.evaluate_policy(str(policy))
        assert result is True

    def test_missing_max_critical_fails(self, engine: RuleFusionEngine) -> None:
        """Policy without max_critical key fails."""
        policy = engine.rules_dir / "policy.json"
        policy.write_text(json.dumps({}))
        result = engine.evaluate_policy(str(policy))
        assert result is False
