import json
import os
import tempfile
from unittest.mock import patch

from devsecops_radar.core.rule_fusion import RuleFusion


def test_update_community_rules_invalid_url():
    engine = RuleFusion(community_repo="https://evil.com/repo.git")
    with patch('subprocess.run') as mock_run:
        engine.update_community_rules()
        mock_run.assert_not_called()  # because URL is invalid


def test_update_community_rules_valid():
    engine = RuleFusion()
    with patch('subprocess.run') as mock_run, patch('pathlib.Path.exists', return_value=False):
        engine.update_community_rules()
        mock_run.assert_called_once()


def test_evaluate_policy_pass():
    findings = [{"severity": "CRITICAL"}] * 2
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({"max_critical": 5}, f)
        f.flush()
        passed, msg = RuleFusion.evaluate_policy(findings, f.name)
    os.unlink(f.name)
    assert passed


def test_evaluate_policy_fail():
    findings = [{"severity": "CRITICAL"}] * 6
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({"max_critical": 5, "on_violation": "fail"}, f)
        f.flush()
        passed, msg = RuleFusion.evaluate_policy(findings, f.name)
    os.unlink(f.name)
    assert not passed
