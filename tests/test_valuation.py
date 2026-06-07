from unittest.mock import patch

from devsecops_radar.core.valuation import (
    ACTIVE_THREAT_MULT,
    BASE_SEVERITY_SCORES,
    EXPLOIT_AVAILABLE_MULT,
    EXPOSURE_MULTIPLIER,
    MAX_RISK_SCORE,
    MIN_RISK_SCORE,
    SENSITIVE_DATA_MULTIPLIER,
    compute_dynamic_risk_score,
    logger,
)


class TestComputeDynamicRiskScore:
    # --- Invalid input -------------------------------------------------
    def test_invalid_finding_not_dict(self):
        with patch.object(logger, "error") as mock_error:
            result = compute_dynamic_risk_score(["not a dict"])
            assert result == 0.0
            mock_error.assert_called_once()

    # --- Base score from severity --------------------------------------
    def test_known_severity_base_only(self):
        finding = {"severity": "HIGH", "id": "CVE-123"}
        expected = BASE_SEVERITY_SCORES["HIGH"]  # 7.0
        assert compute_dynamic_risk_score(finding) == expected

    def test_lowercase_severity_converts(self):
        finding = {"severity": "critical", "id": "CVE-456"}
        expected = BASE_SEVERITY_SCORES["CRITICAL"]  # 9.0
        assert compute_dynamic_risk_score(finding) == expected

    def test_unknown_severity_defaults(self):
        finding = {"severity": "MEGA", "id": "X"}
        with patch.object(logger, "warning") as mock_warn:
            result = compute_dynamic_risk_score(finding)
            assert result == BASE_SEVERITY_SCORES["UNKNOWN"]  # 1.0
            mock_warn.assert_called_once()

    # --- Environmental multipliers (topology) --------------------------
    def test_topology_exposed_true(self):
        finding = {"severity": "MEDIUM", "target": "web-server"}
        topology = {
            "assets": [
                {"name": "web-server", "exposed": True}
            ]
        }
        base = BASE_SEVERITY_SCORES["MEDIUM"]  # 4.0
        expected = base * EXPOSURE_MULTIPLIER  # 4.0 * 1.3 = 5.2
        assert compute_dynamic_risk_score(finding, topology=topology) == round(expected, 1)

    def test_topology_sensitive_data(self):
        finding = {"severity": "LOW", "target": "db"}
        topology = {
            "servers": [
                {"name": "db", "data_classification": "sensitive"}
            ]
        }
        base = BASE_SEVERITY_SCORES["LOW"]  # 1.5
        expected = base * SENSITIVE_DATA_MULTIPLIER  # 1.5 * 1.2 = 1.8
        assert compute_dynamic_risk_score(finding, topology=topology) == round(expected, 1)

    def test_topology_both_multipliers_max(self):
        finding = {"severity": "HIGH", "target": "public-db"}
        topology = {
            "nodes": [
                {"name": "public-db", "exposed": True, "data_classification": "sensitive"}
            ]
        }
        base = BASE_SEVERITY_SCORES["HIGH"]  # 7.0
        env = max(EXPOSURE_MULTIPLIER, SENSITIVE_DATA_MULTIPLIER)  # 1.3
        expected = base * env  # 7.0 * 1.3 = 9.1
        assert compute_dynamic_risk_score(finding, topology=topology) == round(expected, 1)

    def test_topology_no_match(self):
        finding = {"severity": "HIGH", "target": "missing-target"}
        topology = {"assets": [{"name": "other", "exposed": True}]}
        expected = BASE_SEVERITY_SCORES["HIGH"]  # 7.0
        assert compute_dynamic_risk_score(finding, topology=topology) == expected

    def test_topology_subpath_match(self):
        # The code checks "/{asset_name}/" in "/{target}/"
        finding = {"severity": "LOW", "target": "/api/users"}
        topology = {"assets": [{"name": "api", "exposed": True}]}
        base = BASE_SEVERITY_SCORES["LOW"]
        expected = base * EXPOSURE_MULTIPLIER
        assert compute_dynamic_risk_score(finding, topology=topology) == round(expected, 1)

    # --- Threat multipliers (exploit_available in finding & threat_intel) ---
    def test_exploit_available_in_finding(self):
        finding = {"severity": "MEDIUM", "exploit_available": True}
        base = BASE_SEVERITY_SCORES["MEDIUM"]
        expected = base * EXPLOIT_AVAILABLE_MULT  # 4.0 * 1.2 = 4.8
        assert compute_dynamic_risk_score(finding) == round(expected, 1)

    def test_active_threat_multiplier(self):
        finding = {"severity": "HIGH", "id": "CVE-2025-0001"}
        threat_intel = {
            "active_threats": [
                {"cve_id": "CVE-2025-0001", "description": "RCE"}
            ]
        }
        base = BASE_SEVERITY_SCORES["HIGH"]
        base * ACTIVE_THREAT_MULT  # 7.0 * 1.5 = 10.5 → capped to 10.0
        assert compute_dynamic_risk_score(finding, threat_intel=threat_intel) == 10.0

    def test_active_threat_by_rule_id(self):
        finding = {"severity": "LOW", "id": "RULE-001"}
        threat_intel = {
            "active_threats": [
                {"rule_id": "RULE-001", "active": True}
            ]
        }
        base = BASE_SEVERITY_SCORES["LOW"]
        base * ACTIVE_THREAT_MULT  # 1.5 * 1.5 = 2.25 → round(2.3)
        assert compute_dynamic_risk_score(finding, threat_intel=threat_intel) == round(base * ACTIVE_THREAT_MULT, 1)

    def test_both_exploit_and_active_threat_max_multiplier(self):
        finding = {"severity": "CRITICAL", "exploit_available": True, "id": "CVE-2025-0002"}
        threat_intel = {
            "active_threats": [
                {"cve_id": "CVE-2025-0002"}
            ]
        }
        base = BASE_SEVERITY_SCORES["CRITICAL"]  # 9.0
        threat = max(EXPLOIT_AVAILABLE_MULT, ACTIVE_THREAT_MULT)  # 1.5
        base * threat  # 9.0 * 1.5 = 13.5 → capped 10.0
        assert compute_dynamic_risk_score(finding, threat_intel=threat_intel) == 10.0

    # --- Combined environment + threat ---
    def test_full_combination(self):
        finding = {
            "severity": "MEDIUM",
            "target": "api-server",
            "exploit_available": True,
            "id": "CVE-X"
        }
        topology = {
            "assets": [{"name": "api-server", "exposed": True}]
        }
        threat_intel = {
            "active_threats": [{"cve_id": "CVE-X"}]
        }
        base = BASE_SEVERITY_SCORES["MEDIUM"]  # 4.0
        env = EXPOSURE_MULTIPLIER  # 1.3
        threat = max(EXPLOIT_AVAILABLE_MULT, ACTIVE_THREAT_MULT)  # 1.5
        final = base * env * threat  # 4.0 * 1.3 * 1.5 = 7.8
        assert compute_dynamic_risk_score(finding, topology=topology, threat_intel=threat_intel) == round(final, 1)

    # --- Normalization: capping and minimum ----------------------------
    def test_score_capped_at_max(self):
        finding = {"severity": "CRITICAL"}
        # artificially set base to 10, then apply max multipliers
        # But we can't change base; instead we'll just trust the formula: CRITICAL (9) * env (1.3) * threat (1.5) = 17.55 -> capped 10
        finding["exploit_available"] = True
        threat_intel = {"active_threats": [{"cve_id": finding.get("id", "dummy")}]}
        topology = {"assets": [{"name": finding.get("target", "dummy"), "exposed": True}]}
        # need id and target to match
        finding["id"] = "CVE-CAP"
        finding["target"] = "asset"
        topology["assets"][0]["name"] = "asset"
        threat_intel["active_threats"][0]["cve_id"] = "CVE-CAP"
        result = compute_dynamic_risk_score(finding, topology=topology, threat_intel=threat_intel)
        assert result == MAX_RISK_SCORE

    def test_score_minimum_not_below_zero(self):
        finding = {"severity": "LOW"}
        # The minimal would be LOW (1.5) with no multipliers, but if base somehow became negative? Not possible.
        assert compute_dynamic_risk_score(finding) >= MIN_RISK_SCORE
