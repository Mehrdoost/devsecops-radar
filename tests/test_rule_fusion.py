import json
import tempfile
import os
from devsecops_radar.core.rule_fusion import RuleFusion

class TestPolicyEvaluation:
    def test_policy_pass(self):
        findings = [{"severity": "CRITICAL"}] * 3
        policy = {"max_critical": 5, "on_violation": "fail"}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(policy, f)
            f.flush()
            passed, msg = RuleFusion.evaluate_policy(findings, f.name)
        os.unlink(f.name)
        assert passed
        assert "passed" in msg

    def test_policy_fail(self):
        findings = [{"severity": "CRITICAL"}] * 6
        policy = {"max_critical": 5, "on_violation": "fail"}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(policy, f)
            f.flush()
            passed, msg = RuleFusion.evaluate_policy(findings, f.name)
        os.unlink(f.name)
        assert not passed

    def test_policy_file_not_found(self):
        passed, msg = RuleFusion.evaluate_policy([], "/nonexistent/policy.json")
        assert passed