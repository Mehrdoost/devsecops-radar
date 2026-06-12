from types import MappingProxyType
from typing import Any

from loguru import logger

# --- Valuation Constants (Inspired by CVSS Modifiers) ---
# Base scores mapped to standard severities
_BASE_SEVERITY_SCORES: dict[str, float] = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.5,
    "UNKNOWN": 1.0,
}
BASE_SEVERITY_SCORES = MappingProxyType(_BASE_SEVERITY_SCORES)

# Environmental Multipliers (Applied via max() to prevent exponential explosion)
EXPOSURE_MULTIPLIER = 1.3       # Asset is publicly exposed
SENSITIVE_DATA_MULTIPLIER = 1.2 # Asset contains sensitive/PII data

# Threat Intelligence Multipliers
EXPLOIT_AVAILABLE_MULT = 1.2    # Public PoC exists
ACTIVE_THREAT_MULT = 1.5        # Actively exploited in the wild (CISA KEV, etc.)

MAX_RISK_SCORE = 10.0
MIN_RISK_SCORE = 0.0


def _match_target_to_asset(target: str, asset_name: str, asset_id: str) -> bool:
    """
    Safely match a finding's target to a topology asset.
    Uses exact match first, then path‑aware matching.
    """
    if not target or (not asset_name and not asset_id):
        return False
    # Exact match on name or identifier
    if target == asset_name or target == asset_id:
        return True
    # Path‑aware match: split both into components and check exact component equality
    if asset_name:
        target_parts = target.strip("/").split("/")
        asset_parts = asset_name.strip("/").split("/")
        # Match if the asset path is a suffix of the target path (e.g. "app/config" matches "app")
        if len(asset_parts) <= len(target_parts):
            if target_parts[-len(asset_parts):] == asset_parts:
                return True
    return False


def compute_dynamic_risk_score(
    finding: dict[str, Any],
    topology: dict[str, Any] | None = None,
    threat_intel: dict[str, Any] | None = None,
) -> float:
    """
    Computes a dynamic, context-aware risk score (0.0 to 10.0) for a security finding.

    The formula uses a base score derived from the finding's severity, and applies
    environmental multipliers (from topology) and threat multipliers (from threat intel).

    Args:
        finding: Dictionary containing vulnerability details (severity, target, id).
        topology: Optional dictionary defining the infrastructure layout and asset metadata.
        threat_intel: Optional dictionary containing active threat data and known exploits.

    Returns:
        float: A normalized risk score between 0.0 and 10.0.
    """
    if not isinstance(finding, dict):
        logger.error(
            "Invalid finding format provided to valuation engine. "
            "Expected a dictionary."
        )
        return 0.0

    # 1. Base Score Calculation
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

    # 2. Environmental Multipliers (Topology context)
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

    # 3. Threat Intelligence Multipliers
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

    # 4. Final Calculation & Normalization
    final_score = base_score * env_mult * threat_mult
    normalized_score = max(MIN_RISK_SCORE, min(final_score, MAX_RISK_SCORE))

    return round(normalized_score, 1)
