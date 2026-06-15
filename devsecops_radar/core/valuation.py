from types import MappingProxyType
from typing import Any

from loguru import logger

# --- Valuation Constants (Inspired by CVSS Modifiers) ---
_BASE_SEVERITY_SCORES: dict[str, float] = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.5,
    "UNKNOWN": 1.0,
}
BASE_SEVERITY_SCORES = MappingProxyType(_BASE_SEVERITY_SCORES)

EXPOSURE_MULTIPLIER = 1.3
SENSITIVE_DATA_MULTIPLIER = 1.2

EXPLOIT_AVAILABLE_MULT = 1.2
ACTIVE_THREAT_MULT = 1.5

MAX_RISK_SCORE = 10.0
MIN_RISK_SCORE = 0.0


def _match_target_to_asset(target: str, asset_name: str, asset_id: str) -> bool:
    if not target or (not asset_name and not asset_id):
        return False
    if target == asset_name or target == asset_id:
        return True
    if asset_name:
        target_parts = target.strip("/").split("/")
        asset_parts = asset_name.strip("/").split("/")
        if len(asset_parts) <= len(target_parts):
            if target_parts[-len(asset_parts):] == asset_parts:
                return True
    return False


def compute_dynamic_risk_score(
    finding: dict[str, Any],
    topology: dict[str, Any] | None = None,
    threat_intel: dict[str, Any] | None = None,
) -> float:
    if not isinstance(finding, dict):
        logger.error(
            "Invalid finding format provided to valuation engine. "
            "Expected a dictionary."
        )
        return 0.0

    raw_severity = finding.get("severity", "LOW")
    severity = str(raw_severity).strip().upper()

    if severity not in BASE_SEVERITY_SCORES:
        logger.warning(
            f"Unknown severity '{severity}' for finding ID "
            f"{finding.get('id', 'N/A')}. Defaulting to UNKNOWN."
        )
        severity = "UNKNOWN"

    base_score = BASE_SEVERITY_SCORES[severity]
    target = finding.get("target", "")

    env_mult = 1.0
    if topology and isinstance(topology, dict):
        asset_lists = [
            topology.get("assets", []),
            topology.get("servers", []),
            topology.get("services", []),
            topology.get("nodes", []),
        ]

        for asset_group in asset_lists:
            if not isinstance(asset_group, list):
                continue

            for asset in asset_group:
                asset_name = asset.get("name", "")
                asset_id = asset.get("identifier", "")

                if _match_target_to_asset(target, asset_name, asset_id):
                    if asset.get("exposed") is True:
                        env_mult = max(env_mult, EXPOSURE_MULTIPLIER)

                    if asset.get("data_classification") == "sensitive":
                        env_mult = max(env_mult, SENSITIVE_DATA_MULTIPLIER)

    threat_mult = 1.0
    if finding.get("exploit_available") is True:
        threat_mult = max(threat_mult, EXPLOIT_AVAILABLE_MULT)

    if threat_intel and isinstance(threat_intel, dict):
        finding_id = finding.get("id")
        active_threats = threat_intel.get("active_threats", [])

        if isinstance(active_threats, list) and finding_id:
            for threat in active_threats:
                if (
                    threat.get("cve_id") == finding_id
                    or threat.get("rule_id") == finding_id
                ):
                    threat_mult = max(threat_mult, ACTIVE_THREAT_MULT)
                    break

    final_score = base_score * env_mult * threat_mult
    normalized_score = max(MIN_RISK_SCORE, min(final_score, MAX_RISK_SCORE))

    return round(normalized_score, 1)
