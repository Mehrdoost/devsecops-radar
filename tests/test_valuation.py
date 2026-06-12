"""Tests for the dynamic risk valuation engine."""

from contextlib import contextmanager

import pytest
from loguru import logger

from devsecops_radar.core.valuation import (
    _match_target_to_asset,
    compute_dynamic_risk_score,
)


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
def sample_finding():
    return {
        "id": "CVE-2024-1234",
        "severity": "HIGH",
        "target": "web-server/api",
        "exploit_available": False,
    }


@pytest.fixture
def sample_topology():
    return {
        "assets": [
            {
                "name": "web-server/api",
                "identifier": "svc-001",
                "exposed": True,
                "data_classification": "sensitive",
            },
            {
                "name": "db-server",
                "identifier": "svc-002",
                "exposed": False,
                "data_classification": "internal",
            },
        ]
    }


@pytest.fixture
def sample_threat_intel():
    return {
        "active_threats": [
            {"cve_id": "CVE-2024-1234", "description": "Actively exploited"},
            {"rule_id": "semgrep-rule-1", "description": "Ransomware campaign"},
        ]
    }


# ============================================================================
# Tests for _match_target_to_asset
# ============================================================================
class TestMatchTargetToAsset:
    def test_exact_name_match(self):
        assert _match_target_to_asset("web-server", "web-server", "") is True

    def test_exact_id_match(self):
        assert _match_target_to_asset("web-server", "", "web-server") is True

    def test_path_suffix_match(self):
        # Target: "app/config/file.yaml", Asset: "config" (last component of target?)
        # Actually suffix: target_parts = ["app","config","file.yaml"], asset_parts = ["config"]
        # Asset path is a suffix? target_parts[-1:] = ["file.yaml"] ≠ asset_parts = ["config"] – Wait logic:
        # if len(asset_parts) <= len(target_parts): 2 <= 3 → True
        #   if target_parts[-len(asset_parts):] == asset_parts: target_parts[-2:] = ["config","file.yaml"] == ["app","config"]? False
        # So this would not match. We need a case where asset name is a suffix of target path.
        # Let's test with asset "api/v1", target "web-server/api/v1".
        # target parts = ["web-server","api","v1"], asset parts = ["api","v1"] → suffix match (last 2 equal asset).
        assert _match_target_to_asset("web-server/api/v1", "api/v1", "") is True

    def test_path_suffix_no_match(self):
        assert _match_target_to_asset("web-server/api", "api/v2", "") is False

    def test_empty_target(self):
        assert _match_target_to_asset("", "asset", "") is False
        assert _match_target_to_asset("asset", "", "") is False

    def test_no_name_or_id_returns_false(self):
        assert _match_target_to_asset("something", "", "") is False

    def test_handle_slashes_in_target_and_asset(self):
        # Ensure stripping works correctly
        assert _match_target_to_asset("/app/config/", "/app/config/", "") is True


# ============================================================================
# Tests for compute_dynamic_risk_score
# ============================================================================
class TestComputeDynamicRiskScore:
    def test_invalid_finding_returns_zero(self):
        with capture_loguru() as msgs:
            result = compute_dynamic_risk_score(None)
        assert result == 0.0
        assert any("Invalid finding format" in m for m in msgs)

        with capture_loguru() as msgs:
            result = compute_dynamic_risk_score("not-a-dict")
        assert result == 0.0

    def test_default_severity_low(self):
        finding = {}  # missing severity defaults to "LOW"
        score = compute_dynamic_risk_score(finding)
        assert score == 1.5  # LOW = 1.5, no multipliers

    def test_unknown_severity(self):
        finding = {"severity": "WARNING"}
        with capture_loguru() as msgs:
            score = compute_dynamic_risk_score(finding)
        assert score == 1.0  # UNKNOWN = 1.0
        assert any("Unknown severity" in m for m in msgs)

    def test_base_score_critical(self):
        finding = {"severity": "CRITICAL"}
        score = compute_dynamic_risk_score(finding)
        assert score == 9.0

    def test_environmental_multiplier_exposed(self, sample_finding, sample_topology):
        # finding target matches exposed asset → env_mult = max(1.0, 1.3) = 1.3
        score = compute_dynamic_risk_score(sample_finding, sample_topology)
        # base (HIGH=7.0) * 1.3 = 9.1
        assert score == 9.1

    def test_environmental_multiplier_sensitive_data(
        self, sample_finding, sample_topology
    ):
        # Same as above but we'll also test sensitive data alone? Both are set, so result same.
        # The asset is both exposed and sensitive, env_mult = max(1.0, 1.3, 1.2) = 1.3.
        # To test sensitive alone, remove exposed flag.
        topo = {
            "assets": [
                {
                    "name": "web-server/api",
                    "exposed": False,
                    "data_classification": "sensitive",
                }
            ]
        }
        score = compute_dynamic_risk_score(sample_finding, topo)
        # base 7.0 * 1.2 = 8.4
        assert score == 8.4

    def test_environmental_no_match(self, sample_finding):
        topo = {"assets": [{"name": "other-service", "exposed": True}]}
        score = compute_dynamic_risk_score(sample_finding, topo)
        assert score == 7.0  # no multiplier

    def test_multiple_asset_groups(self):
        finding = {"target": "myapp", "severity": "MEDIUM"}
        topo = {
            "services": [{"name": "myapp", "exposed": True}],
            "nodes": [{"name": "myapp", "data_classification": "sensitive"}],
        }
        score = compute_dynamic_risk_score(finding, topo)
        # base 4.0 * max(1.3,1.2) = 4.0 * 1.3 = 5.2
        assert score == 5.2

    def test_threat_intel_exploit_available(self, sample_finding):
        sample_finding["exploit_available"] = True
        score = compute_dynamic_risk_score(sample_finding)
        # base 7.0 * 1.2 = 8.4
        assert score == 8.4

    def test_threat_intel_active_threat_matching_cve(
        self, sample_finding, sample_threat_intel
    ):
        score = compute_dynamic_risk_score(
            sample_finding, threat_intel=sample_threat_intel
        )
        # base 7.0 * ACTIVE_THREAT_MULT(1.5) = 10.5 capped to 10.0
        assert score == 10.0

    def test_threat_intel_active_threat_matching_rule_id(self):
        finding = {"id": "semgrep-rule-1", "severity": "HIGH"}
        threat_intel = {
            "active_threats": [{"rule_id": "semgrep-rule-1"}]
        }
        score = compute_dynamic_risk_score(finding, threat_intel=threat_intel)
        assert score == 10.0  # 7.0 * 1.5 = 10.5 capped

    def test_threat_intel_no_match(self, sample_finding, sample_threat_intel):
        # finding id not in active_threats
        sample_finding["id"] = "CVE-9999"
        score = compute_dynamic_risk_score(
            sample_finding, threat_intel=sample_threat_intel
        )
        # no threat multiplier, no env → 7.0
        assert score == 7.0

    def test_combined_multipliers(
        self, sample_finding, sample_topology, sample_threat_intel
    ):
        # Exposed + sensitive + active threat (CVE-2024-1234)
        score = compute_dynamic_risk_score(
            sample_finding, sample_topology, sample_threat_intel
        )
        # base 7.0 * env_max(1.3,1.2)=1.3 * threat 1.5 = 7.0 * 1.95 = 13.65 capped 10.0
        assert score == 10.0

    def test_capping_at_max_score(self):
        topo = {
            "assets": [
                {
                    "name": "any",
                    "identifier": "any",
                    "exposed": True,
                    "data_classification": "sensitive",
                }
            ]
        }
        threat_intel = {"active_threats": [{"cve_id": "any"}]}
        # target matches? target is empty, so no match for env, but exploit_available and active_threat still apply.
        # Actually target is missing, so no env match. But threat multipliers: exploit_available=1.2, active_threat=1.5 → threat_mult = 1.5.
        # base 9.0 * 1.5 = 13.5 capped 10.0.
        # To test env we'd need target matching. Let's keep it simple.
        # Use an env match too:
        finding_with_target = {
            "severity": "CRITICAL",
            "target": "any",
            "exploit_available": True,
        }
        score = compute_dynamic_risk_score(
            finding_with_target, topo, threat_intel
        )
        # env mult 1.3 (exposed), threat mult max(1.2, 1.5)=1.5 => 9.0*1.3*1.5 = 17.55 capped 10.0
        assert score == 10.0

    def test_capping_at_min_score(self):
        finding = {"severity": "LOW"}  # 1.5, no multipliers
        score = compute_dynamic_risk_score(finding)
        assert score == 1.5  # above min

    def test_rounding_to_one_decimal(self):
        finding = {"severity": "MEDIUM"}
        topo = {
            "assets": [
                {
                    "name": "anything",
                    "identifier": "any",
                    "exposed": True,
                    "data_classification": "sensitive",
                }
            ]
        }
        finding["target"] = "anything"
        # base 4.0 * 1.3 = 5.2 (exact one decimal)
        score = compute_dynamic_risk_score(finding, topo)
        assert score == 5.2
        # Check rounding: 4.0 * 1.3 = 5.2, already round. Another case: 4.0 * 1.2 = 4.8.
        finding2 = {"severity": "MEDIUM", "target": "anything"}
        topo2 = {
            "assets": [
                {"name": "anything", "data_classification": "sensitive"}
            ]
        }
        score2 = compute_dynamic_risk_score(finding2, topo2)
        assert score2 == 4.8
