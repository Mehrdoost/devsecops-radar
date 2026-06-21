# devsecops_radar/core/valuation.py
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


def _match_target_to_asset(target: str, asset: dict) -> bool:
    """Determine if *target* corresponds to the given *asset*.

    The matching logic now covers several common representations:
    - Exact match on asset's ``name`` or ``identifier`` (ID / IP / DNS).
    - If *target* is a file path and the asset has a matching ``path`` attribute.
    - If *target* looks like an IP address, compare with asset's ``ip`` or ``identifier``.
    """
    if not target or not isinstance(asset, dict):
        return False

    target_lower = target.lower()

    # 1. Exact match on common fields
    for field in ("name", "identifier", "id", "ip", "hostname", "dns", "path"):
        val = asset.get(field)
        if isinstance(val, str) and val.lower() == target_lower:
            return True

    # 2. Suffix match for file paths (e.g. target "/app/config.yaml" matches asset path "/app")
    asset_path = asset.get("path")
    if asset_path and isinstance(asset_path, str):
        if target.startswith(asset_path) or asset_path.startswith(target):
            return True

    # 3. IP/CIDR fuzzy match (basic)
    # If target looks like an IP and asset has an "ip" field, compare
    target_ip = target.split(":")[0]  # strip port
    asset_ip = asset.get("ip", "")
    if target_ip and asset_ip and target_ip == asset_ip:
        return True

    return False


def compute_dynamic_risk_score(
    finding: dict[str, Any],
    topology: dict[str, Any] | None = None,
    threat_intel: dict[str, Any] | None = None,
) -> float:
    """Calculate a dynamic (0‑10) risk score for a single finding.

    The score is derived from the base severity and then multiplied by
    environmental (topology) and threat‑intelligence modifiers.
    """
    if not isinstance(finding, dict):
        logger.error("Invalid finding format provided to valuation engine.")
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

    # --- Environmental (topology) multipliers ---
    env_mult = 1.0
    if topology and isinstance(topology, dict):
        # Gather asset lists from common topology keys
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
                if not isinstance(asset, dict):
                    continue
                if _match_target_to_asset(target, asset):
                    if asset.get("exposed") is True:
                        env_mult = max(env_mult, EXPOSURE_MULTIPLIER)
                    if asset.get("data_classification") == "sensitive":
                        env_mult = max(env_mult, SENSITIVE_DATA_MULTIPLIER)
                    # We don't break here – an asset could match multiple criteria

    # --- Threat intelligence multipliers ---
    threat_mult = 1.0

    # Exploit available flag (from scanner rule or custom override)
    if finding.get("exploit_available") is True:
        threat_mult = max(threat_mult, EXPLOIT_AVAILABLE_MULT)

    # External threat intel
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

    # Combine and clamp
    final_score = base_score * env_mult * threat_mult
    normalized_score = max(MIN_RISK_SCORE, min(final_score, MAX_RISK_SCORE))
    return round(normalized_score, 1)
