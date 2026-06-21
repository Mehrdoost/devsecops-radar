"""Tests for valuation module – updated for new _match_target_to_asset and removed invalid test."""

from unittest.mock import patch

from devsecops_radar.core.valuation import (
    BASE_SEVERITY_SCORES,
    MAX_RISK_SCORE,
    _match_target_to_asset,
    compute_dynamic_risk_score,
)


# ============================================================================
# Tests for _match_target_to_asset
# ============================================================================
class TestMatchTargetToAsset:
    def test_exact_match_name(self):
        assert _match_target_to_asset("server1", {"name": "server1"}) is True

    def test_exact_match_identifier(self):
        assert _match_target_to_asset("10.0.0.1", {"identifier": "10.0.0.1"}) is True

    def test_exact_match_ip_field(self):
        assert _match_target_to_asset("10.0.0.1", {"ip": "10.0.0.1"}) is True

    def test_exact_match_hostname(self):
        assert _match_target_to_asset("db.example.com", {"hostname": "db.example.com"}) is True

    def test_exact_match_dns(self):
        assert _match_target_to_asset("api.example.com", {"dns": "api.example.com"}) is True

    def test_exact_match_path(self):
        assert _match_target_to_asset("/app/config.yaml", {"path": "/app/config.yaml"}) is True

    def test_case_insensitive_match(self):
        assert _match_target_to_asset("Server1", {"name": "server1"}) is True

    def test_no_match_different_values(self):
        assert _match_target_to_asset("server1", {"name": "server2"}) is False

    def test_empty_target(self):
        assert _match_target_to_asset("", {"name": "server1"}) is False

    def test_none_asset(self):
        assert _match_target_to_asset("server1", None) is False

    def test_non_dict_asset(self):
        assert _match_target_to_asset("server1", "string") is False

    def test_path_prefix_match_target_starts_with_asset(self):
        assert _match_target_to_asset("/app/config/config.yaml", {"path": "/app"}) is True

    def test_path_prefix_match_asset_starts_with_target(self):
        assert _match_target_to_asset("/app", {"path": "/app/config"}) is True

    def test_path_no_prefix_match(self):
        assert _match_target_to_asset("/other/config.yaml", {"path": "/app"}) is False

    def test_ip_match_with_port_stripping(self):
        assert _match_target_to_asset("10.0.0.1:8080", {"ip": "10.0.0.1"}) is True

    def test_ip_match_no_port(self):
        assert _match_target_to_asset("10.0.0.1", {"ip": "10.0.0.1"}) is True

    def test_ip_mismatch(self):
        assert _match_target_to_asset("10.0.0.2", {"ip": "10.0.0.1"}) is False

    def test_multiple_fields_one_matches(self):
        asset = {"name": "web", "ip": "10.0.0.1", "hostname": "db.example.com"}
        assert _match_target_to_asset("10.0.0.1", asset) is True

    def test_no_fields_match(self):
        asset = {"name": "web", "ip": "10.0.0.1"}
        assert _match_target_to_asset("10.0.0.2", asset) is False

    def test_id_field_exact_match(self):
        assert _match_target_to_asset("node-5", {"id": "node-5"}) is True


# ============================================================================
# Tests for compute_dynamic_risk_score
# ============================================================================
class TestComputeDynamicRiskScore:
    def test_invalid_finding_returns_zero(self):
        assert compute_dynamic_risk_score(None) == 0.0
        assert compute_dynamic_risk_score("not a dict") == 0.0

    def test_unknown_severity_defaults_to_unknown_score(self):
        finding = {"severity": "CATASTROPHIC", "target": "test"}
        result = compute_dynamic_risk_score(finding)
        assert result == BASE_SEVERITY_SCORES["UNKNOWN"]

    def test_base_score_only(self):
        finding = {"severity": "CRITICAL", "target": "app.py"}
        result = compute_dynamic_risk_score(finding)
        assert result == BASE_SEVERITY_SCORES["CRITICAL"]

    def test_topology_exposed_multiplier(self):
        finding = {"severity": "HIGH", "target": "server.example.com"}
        topology = {
            "assets": [
                {
                    "name": "server.example.com",
                    "exposed": True,
                }
            ]
        }
        expected = round(BASE_SEVERITY_SCORES["HIGH"] * 1.3, 1)
        assert compute_dynamic_risk_score(finding, topology) == expected

    def test_topology_sensitive_data_multiplier(self):
        finding = {"severity": "MEDIUM", "target": "db.internal"}
        topology = {
            "assets": [
                {
                    "name": "db.internal",
                    "data_classification": "sensitive",
                }
            ]
        }
        expected = round(BASE_SEVERITY_SCORES["MEDIUM"] * 1.2, 1)
        assert compute_dynamic_risk_score(finding, topology) == expected

    def test_topology_exposed_and_sensitive_combined(self):
        finding = {"severity": "HIGH", "target": "payment.example.com"}
        topology = {
            "assets": [
                {
                    "name": "payment.example.com",
                    "exposed": True,
                    "data_classification": "sensitive",
                }
            ]
        }
        # env_mult = max(1.3, 1.2) = 1.3
        expected = round(BASE_SEVERITY_SCORES["HIGH"] * 1.3, 1)
        assert compute_dynamic_risk_score(finding, topology) == expected

    def test_topology_no_match_returns_base_score(self):
        finding = {"severity": "LOW", "target": "unknown.service"}
        topology = {"assets": [{"name": "known.service", "exposed": True}]}
        result = compute_dynamic_risk_score(finding, topology)
        assert result == BASE_SEVERITY_SCORES["LOW"]

    def test_topology_with_multiple_asset_lists(self):
        finding = {"severity": "LOW", "target": "10.0.0.1"}
        topology = {
            "servers": [
                {"identifier": "10.0.0.1", "exposed": True}
            ]
        }
        expected = round(BASE_SEVERITY_SCORES["LOW"] * 1.3, 1)
        assert compute_dynamic_risk_score(finding, topology) == expected

    def test_exploit_available_multiplier(self):
        finding = {"severity": "HIGH", "target": "app", "exploit_available": True}
        expected = round(BASE_SEVERITY_SCORES["HIGH"] * 1.2, 1)
        assert compute_dynamic_risk_score(finding) == expected

    def test_threat_intel_active_threat(self):
        finding = {"severity": "MEDIUM", "target": "any", "id": "CVE-999"}
        threat_intel = {"active_threats": [{"cve_id": "CVE-999"}]}
        expected = round(BASE_SEVERITY_SCORES["MEDIUM"] * 1.5, 1)
        assert compute_dynamic_risk_score(finding, threat_intel=threat_intel) == expected

    def test_threat_intel_rule_id_match(self):
        finding = {"severity": "LOW", "target": "any", "id": "RULE-1"}
        threat_intel = {"active_threats": [{"rule_id": "RULE-1"}]}
        expected = round(BASE_SEVERITY_SCORES["LOW"] * 1.5, 1)
        assert compute_dynamic_risk_score(finding, threat_intel=threat_intel) == expected

    def test_threat_intel_no_match(self):
        finding = {"severity": "LOW", "target": "any", "id": "CVE-000"}
        threat_intel = {"active_threats": [{"cve_id": "CVE-999"}]}
        result = compute_dynamic_risk_score(finding, threat_intel=threat_intel)
        assert result == BASE_SEVERITY_SCORES["LOW"]

    def test_all_multipliers_combined(self):
        finding = {
            "severity": "CRITICAL",
            "target": "public.example.com",
            "exploit_available": True,
            "id": "CVE-2024",
        }
        topology = {
            "assets": [
                {
                    "name": "public.example.com",
                    "exposed": True,
                    "data_classification": "sensitive",
                }
            ]
        }
        threat_intel = {"active_threats": [{"cve_id": "CVE-2024"}]}
        # env_mult = max(1.3, 1.2) = 1.3, threat_mult = max(1.2, 1.5) = 1.5
        expected = round(
            BASE_SEVERITY_SCORES["CRITICAL"] * 1.3 * 1.5, 1
        )
        result = compute_dynamic_risk_score(finding, topology, threat_intel)
        assert result == min(expected, MAX_RISK_SCORE)

    def test_clamps_to_max_score(self):
        finding = {"severity": "CRITICAL", "target": "any"}
        with patch(
            "devsecops_radar.core.valuation.EXPOSURE_MULTIPLIER", 100.0
        ), patch(
            "devsecops_radar.core.valuation.SENSITIVE_DATA_MULTIPLIER", 1.0
        ), patch(
            "devsecops_radar.core.valuation.EXPLOIT_AVAILABLE_MULT", 1.0
        ), patch(
            "devsecops_radar.core.valuation.ACTIVE_THREAT_MULT", 1.0
        ):
            topology = {"assets": [{"name": "any", "exposed": True}]}
            result = compute_dynamic_risk_score(finding, topology)
            assert result == MAX_RISK_SCORE
