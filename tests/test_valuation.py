"""Tests for dynamic risk scoring."""

from devsecops_radar.core.valuation import compute_dynamic_risk_score


class TestDynamicRiskScore:
    def test_basic_finding_no_extra_context(self):
        finding = {"severity": "HIGH", "id": "CVE-123", "target": "web-server"}
        score = compute_dynamic_risk_score(finding)
        assert score == 7.0  # HIGH = 7.0 base, no multipliers

    def test_critical_severity(self):
        finding = {"severity": "CRITICAL", "id": "CVE-999", "target": "db"}
        score = compute_dynamic_risk_score(finding)
        assert score == 10.0

    def test_low_severity(self):
        finding = {"severity": "LOW", "id": "CVE-001", "target": "log-collector"}
        score = compute_dynamic_risk_score(finding)
        assert score == 1.0

    def test_exposed_asset(self):
        finding = {"severity": "MEDIUM", "id": "CVE-456", "target": "web-server"}
        topology = {"servers": [{"name": "web-server", "exposed": True}]}
        score = compute_dynamic_risk_score(finding, topology=topology)
        # base 4.0 * 2.5 = 10.0, capped at 10.0
        assert score == 10.0

    def test_sensitive_asset(self):
        finding = {"severity": "MEDIUM", "id": "CVE-456", "target": "db-server"}
        topology = {"servers": [{"name": "db-server", "data_classification": "sensitive"}]}
        score = compute_dynamic_risk_score(finding, topology=topology)
        # base 4.0 * 1.5 = 6.0
        assert score == 6.0

    def test_exposed_and_sensitive(self):
        finding = {"severity": "HIGH", "id": "CVE-789", "target": "payment-api"}
        topology = {"servers": [{"name": "payment-api", "exposed": True, "data_classification": "sensitive"}]}
        score = compute_dynamic_risk_score(finding, topology=topology)
        # base 7.0 * 2.5 * 1.5 = 26.25 -> capped 10.0
        assert score == 10.0

    def test_topology_no_match(self):
        finding = {"severity": "HIGH", "id": "CVE-000", "target": "unknown-service"}
        topology = {"servers": [{"name": "web-server", "exposed": True}]}
        score = compute_dynamic_risk_score(finding, topology=topology)
        # no match -> exposure_mult stays 1.0
        assert score == 7.0

    def test_exploit_available(self):
        finding = {"severity": "MEDIUM", "id": "CVE-111", "target": "app", "exploit_available": True}
        score = compute_dynamic_risk_score(finding)
        # base 4.0 * 2.0 = 8.0
        assert score == 8.0

    def test_threat_intel_match(self):
        finding = {"severity": "LOW", "id": "CVE-ACTIVE", "target": "x"}
        threat_intel = {"active_threats": [{"cve_id": "CVE-ACTIVE"}]}
        score = compute_dynamic_risk_score(finding, threat_intel=threat_intel)
        # base 1.0 * 2.5 = 2.5
        assert score == 2.5

    def test_threat_intel_no_match(self):
        finding = {"severity": "LOW", "id": "CVE-INACTIVE", "target": "y"}
        threat_intel = {"active_threats": [{"cve_id": "CVE-OTHER"}]}
        score = compute_dynamic_risk_score(finding, threat_intel=threat_intel)
        # no match -> 1.0
        assert score == 1.0

    def test_all_factors_combined(self):
        finding = {
            "severity": "CRITICAL",
            "id": "CVE-ALL",
            "target": "public-api",
            "exploit_available": True,
        }
        topology = {"servers": [{"name": "public-api", "exposed": True, "data_classification": "sensitive"}]}
        threat_intel = {"active_threats": [{"cve_id": "CVE-ALL"}]}
        score = compute_dynamic_risk_score(finding, topology=topology, threat_intel=threat_intel)
        # base 10.0 * 2.5 (exposed) * 1.5 (sensitive) * 2.0 (exploit) * 2.5 (threat) = 187.5 -> capped 10.0
        assert score == 10.0
