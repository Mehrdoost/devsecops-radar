import json
import warnings
from typing import List, Dict, Any

warnings.warn(
    "devsecops_radar.core.parser is deprecated and will be removed in v0.3.0. "
    "Use devsecops_radar.core.rule_fusion.RuleFusion instead.",
    DeprecationWarning,
    stacklevel=2,
)

def parse_trivy_json(file_path: str) -> List[Dict[str, Any]]:
    with open(file_path) as f:
        data = json.load(f)
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "Unknown")
        for vuln in result.get("Vulnerabilities", []):
            findings.append(
                {
                    "tool": "Trivy",
                    "target": target,
                    "id": vuln.get("VulnerabilityID"),
                    "severity": vuln.get("Severity", "UNKNOWN").upper(),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                }
            )
    return findings


def parse_semgrep_json(file_path: str) -> List[Dict[str, Any]]:
    with open(file_path) as f:
        data = json.load(f)
    findings = []
    for result in data.get("results", []):
        findings.append(
            {
                "tool": "Semgrep",
                "target": result.get("path", ""),
                "id": result.get("check_id", ""),
                "severity": result.get("extra", {})
                .get("severity", "WARNING")
                .upper(),
                "title": result.get("check_id", ""),
                "description": result.get("extra", {}).get("message", ""),
                "line": result.get("start", {}).get("line", 0),
            }
        )
    return findings


def merge_findings(*finding_lists) -> List[Dict[str, Any]]:
    merged = []
    for lst in finding_lists:
        merged.extend(lst)
    return merged