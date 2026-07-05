# tests/test_valuation.py
"""Tests for the dynamic risk scoring engine with topology and threat‑intel
modifiers, target matching, and clamping.
"""

from __future__ import annotations

from typing import Any

from devsecops_radar.core.valuation import (
    ACTIVE_THREAT_MULT,
    BASE_SEVERITY_SCORES,
    EXPLOIT_AVAILABLE_MULT,
    EXPOSURE_MULTIPLIER,
    MAX_RISK_SCORE,
    MIN_RISK_SCORE,
    SENSITIVE_DATA_MULTIPLIER,
    compute_dynamic_risk_score,
)


class TestComputeDynamicRiskScore:
    def test_known_severity_returns_base_score(self) -> None:
        finding = {"severity": "HIGH", "target": "example.com"}
        score = compute_dynamic_risk_score(finding)
        assert score == BASE_SEVERITY_SCORES["HIGH"]

    def test_unknown_severity_defaults_to_unknown(self) -> None:
        finding = {"severity": "INVALID", "target": "x"}
        score = compute_dynamic_risk_score(finding)
        assert score == BASE_SEVERITY_SCORES["UNKNOWN"]

    def test_missing_severity_defaults_to_low(self) -> None:
        finding = {"target": "x"}
        score = compute_dynamic_risk_score(finding)
        assert score == BASE_SEVERITY_SCORES["LOW"]

    def test_empty_finding_returns_low_score(self) -> None:
        """Empty dict defaults to LOW severity -> 1.5"""
        assert compute_dynamic_risk_score({}) == 1.5

    def test_non_dict_finding_returns_zero(self) -> None:
        # mypy expects dict but the runtime handles any type gracefully
        assert compute_dynamic_risk_score(None) == 0.0  # type: ignore[arg-type]

    def test_topology_exposed_multiplier(self) -> None:
        finding: dict[str, Any] = {"severity": "MEDIUM", "target": "api.example.com"}
        topology: dict[str, Any] = {"assets": [{"name": "api.example.com", "exposed": True}]}
        expected = round(BASE_SEVERITY_SCORES["MEDIUM"] * EXPOSURE_MULTIPLIER, 1)
        score = compute_dynamic_risk_score(finding, topology)
        assert score == expected

    def test_topology_exposed_and_sensitive_combined(self) -> None:
        finding: dict[str, Any] = {"severity": "HIGH", "target": "payment.example.com"}
        topology: dict[str, Any] = {
            "assets": [
                {
                    "name": "payment.example.com",
                    "exposed": True,
                    "data_classification": "sensitive",
                }
            ]
        }
        raw = BASE_SEVERITY_SCORES["HIGH"] * EXPOSURE_MULTIPLIER * SENSITIVE_DATA_MULTIPLIER
        expected = round(min(raw, MAX_RISK_SCORE), 1)
        score = compute_dynamic_risk_score(finding, topology)
        assert score == expected

    def test_topology_does_not_apply_twice(self) -> None:
        finding: dict[str, Any] = {"severity": "MEDIUM", "target": "srv"}
        topology: dict[str, Any] = {
            "assets": [
                {"name": "srv", "exposed": True},
                {"name": "srv", "exposed": True},
            ]
        }
        expected = round(BASE_SEVERITY_SCORES["MEDIUM"] * EXPOSURE_MULTIPLIER, 1)
        score = compute_dynamic_risk_score(finding, topology)
        assert score == expected

    def test_topology_services_array(self) -> None:
        finding: dict[str, Any] = {"severity": "LOW", "target": "db"}
        topology: dict[str, Any] = {"services": [{"name": "db", "data_classification": "sensitive"}]}
        expected = round(BASE_SEVERITY_SCORES["LOW"] * SENSITIVE_DATA_MULTIPLIER, 1)
        score = compute_dynamic_risk_score(finding, topology)
        assert score == expected

    def test_topology_no_match_leaves_score_unchanged(self) -> None:
        finding: dict[str, Any] = {"severity": "CRITICAL", "target": "unknown-host"}
        topology: dict[str, Any] = {"assets": [{"name": "other", "exposed": True}]}
        assert compute_dynamic_risk_score(finding, topology) == BASE_SEVERITY_SCORES["CRITICAL"]

    def test_exploit_available_increases_score(self) -> None:
        finding: dict[str, Any] = {"severity": "HIGH", "target": "app", "exploit_available": True}
        expected = round(BASE_SEVERITY_SCORES["HIGH"] * EXPLOIT_AVAILABLE_MULT, 1)
        assert compute_dynamic_risk_score(finding) == expected

    def test_active_threat_increases_score(self) -> None:
        finding: dict[str, Any] = {"severity": "HIGH", "target": "app", "id": "CVE-2024-9999"}
        threat_intel: dict[str, Any] = {"active_threats": [{"cve_id": "CVE-2024-9999"}]}
        raw = BASE_SEVERITY_SCORES["HIGH"] * ACTIVE_THREAT_MULT
        expected = round(min(raw, MAX_RISK_SCORE), 1)
        assert compute_dynamic_risk_score(finding, threat_intel=threat_intel) == expected

    def test_threat_intel_no_match_no_change(self) -> None:
        finding: dict[str, Any] = {"severity": "HIGH", "target": "app", "id": "CVE-2024-0001"}
        threat_intel: dict[str, Any] = {"active_threats": [{"cve_id": "CVE-2024-9999"}]}
        assert compute_dynamic_risk_score(finding, threat_intel=threat_intel) == BASE_SEVERITY_SCORES["HIGH"]

    def test_all_multipliers_combined(self) -> None:
        finding: dict[str, Any] = {
            "severity": "CRITICAL",
            "target": "payment.example.com",
            "exploit_available": True,
            "id": "CVE-2024-9999",
        }
        topology: dict[str, Any] = {
            "assets": [{"name": "payment.example.com", "exposed": True}],
            "services": [{"name": "payment.example.com", "data_classification": "sensitive"}],
        }
        threat_intel: dict[str, Any] = {"active_threats": [{"cve_id": "CVE-2024-9999"}]}
        raw = (
            BASE_SEVERITY_SCORES["CRITICAL"]
            * EXPOSURE_MULTIPLIER
            * SENSITIVE_DATA_MULTIPLIER
            * EXPLOIT_AVAILABLE_MULT
            * ACTIVE_THREAT_MULT
        )
        expected = round(min(raw, MAX_RISK_SCORE), 1)
        score = compute_dynamic_risk_score(finding, topology, threat_intel)
        assert score == expected

    def test_score_never_below_min(self) -> None:
        finding: dict[str, Any] = {"severity": "LOW"}
        assert compute_dynamic_risk_score(finding) >= MIN_RISK_SCORE

    def test_score_never_above_max(self) -> None:
        finding: dict[str, Any] = {
            "severity": "CRITICAL",
            "target": "x",
            "exploit_available": True,
        }
        score = compute_dynamic_risk_score(finding)
        assert score <= MAX_RISK_SCORE

    def test_topology_poisoning_limit(self) -> None:
        finding: dict[str, Any] = {"severity": "HIGH", "target": "target-499"}
        topology: dict[str, Any] = {"assets": [{"name": f"target-{i}", "exposed": True} for i in range(600)]}
        score = compute_dynamic_risk_score(finding, topology)
        assert score > BASE_SEVERITY_SCORES["HIGH"]
