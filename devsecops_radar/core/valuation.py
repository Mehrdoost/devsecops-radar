from typing import Any


def compute_dynamic_risk_score(
    finding: dict[str, Any],
    topology: dict[str, Any] | None = None,
    threat_intel: dict[str, Any] | None = None
) -> float:
    severity_weights = {'CRITICAL': 10.0, 'HIGH': 7.0, 'MEDIUM': 4.0, 'LOW': 1.0}
    base = severity_weights.get(finding.get('severity', 'LOW'), 1.0)

    exposure_mult = 1.0
    if topology:
        target = finding.get('target', '')
        for server in topology.get('servers', []):
            if server.get('name') in target:
                if server.get('exposed', False):
                    exposure_mult = 2.5
                if server.get('data_classification') == 'sensitive':
                    exposure_mult *= 1.5
                break

    likelihood_mult = 1.0
    if finding.get('exploit_available', False):
        likelihood_mult *= 2.0

    # Threat intelligence multiplier (e.g., actively exploited in the wild)
    if threat_intel:
        for intel in threat_intel.get("active_threats", []):
            if intel.get("cve_id") == finding.get("id"):
                likelihood_mult *= 2.5
                break

    score = base * exposure_mult * likelihood_mult
    return round(min(10.0, score), 1)
