# devsecops_radar/core/valuation.py
"""
Dynamic risk scoring engine with topology‑aware and threat‑intel modifiers.
Multipliers are applied at most once regardless of how many assets match.
"""

from __future__ import annotations

import ipaddress
from types import MappingProxyType
from typing import Any
from urllib.parse import urlparse

from loguru import logger

# ---------------------------------------------------------------------------
# Constants (CVSS‑inspired)
# ---------------------------------------------------------------------------
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

# Prevent topology poisoning – limit the number of assets processed
MAX_TOPOLOGY_ASSETS = 500


# ---------------------------------------------------------------------------
# Topology matching helpers
# ---------------------------------------------------------------------------
def _hostname_from_target(target: str) -> str | None:
    if target.startswith(("http://", "https://")):
        try:
            parsed = urlparse(target)
            return parsed.hostname
        except Exception:
            return None
    return None


def _ip_from_target(target: str) -> str | None:
    ip = target.split(":")[0]
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None


def _match_target_to_asset(target: str, asset: dict) -> bool:
    if not target or not isinstance(asset, dict):
        return False

    target_lower = target.lower()

    # 1. Exact match on common fields
    for field in ("name", "identifier", "id", "ip", "hostname", "dns"):
        val = asset.get(field)
        if isinstance(val, str) and val.lower() == target_lower:
            return True

    # 2. IP match
    target_ip = _ip_from_target(target)
    asset_ip = asset.get("ip")
    if target_ip and isinstance(asset_ip, str) and target_ip == asset_ip:
        return True

    # 3. Hostname match
    target_host = _hostname_from_target(target) or target_lower
    asset_host = asset.get("hostname") or asset.get("dns")
    if isinstance(asset_host, str) and asset_host.lower() == target_host:
        return True

    # 4. Path matching – only if target looks like a file path and asset has "path"
    asset_path = asset.get("path")
    if asset_path and isinstance(asset_path, str) and target.startswith("/"):
        if len(asset_path) > 2 and target.startswith(asset_path.rstrip("/") + "/"):
            return True

    return False


# ---------------------------------------------------------------------------
# Main scoring function
# ---------------------------------------------------------------------------
def compute_dynamic_risk_score(
    finding: dict[str, Any],
    topology: dict[str, Any] | None = None,
    threat_intel: dict[str, Any] | None = None,
) -> float:
    """Calculate a dynamic (0‑10) risk score for a single finding."""
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
    exposed_applied = False
    sensitive_applied = False
    asset_count = 0
    stop = False

    if topology and isinstance(topology, dict):
        asset_lists: list[list[dict]] = []
        for key in ("assets", "servers", "services", "nodes"):
            val = topology.get(key)
            if isinstance(val, list):
                asset_lists.append(val)

        for asset_group in asset_lists:
            if stop:
                break
            for asset in asset_group:
                if not isinstance(asset, dict):
                    continue
                asset_count += 1
                if asset_count > MAX_TOPOLOGY_ASSETS:
                    stop = True
                    break

                if _match_target_to_asset(target, asset):
                    if not exposed_applied and asset.get("exposed") is True:
                        env_mult *= EXPOSURE_MULTIPLIER
                        exposed_applied = True
                    if not sensitive_applied and asset.get("data_classification") == "sensitive":
                        env_mult *= SENSITIVE_DATA_MULTIPLIER
                        sensitive_applied = True
                    # If both have been applied, we can break out of this group
                    if exposed_applied and sensitive_applied:
                        break

        env_mult = min(env_mult, 4.0)

    # --- Threat intelligence multipliers ---
    threat_mult = 1.0

    if finding.get("exploit_available") is True:
        threat_mult *= EXPLOIT_AVAILABLE_MULT

    if threat_intel and isinstance(threat_intel, dict):
        finding_id = finding.get("id")
        active_threats = threat_intel.get("active_threats", [])
        if isinstance(active_threats, list) and finding_id:
            for threat in active_threats:
                if (
                    threat.get("cve_id") == finding_id
                    or threat.get("rule_id") == finding_id
                ):
                    threat_mult *= ACTIVE_THREAT_MULT
                    break

    # Combine and clamp
    final_score = base_score * env_mult * threat_mult
    normalized_score = max(MIN_RISK_SCORE, min(final_score, MAX_RISK_SCORE))
    return round(normalized_score, 1)
