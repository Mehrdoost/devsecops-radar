# devsecops_radar/core/sarif_export.py
"""
SARIF and CycloneDX export with full sensitive data redaction,
atomic writes, and unique rule identifiers.
"""

from __future__ import annotations

import json
import urllib.parse
from datetime import UTC, datetime
from typing import Any

from loguru import logger

from devsecops_radar.core.path_security import atomic_write, resolve_safe_path
from devsecops_radar.core.reporting import redact_sensitive


def _safe_int(val: Any, default: int = 1) -> int:
    try:
        res = int(val)
        return res if res > 0 else default
    except (ValueError, TypeError):
        return default


def _best_id(finding: dict[str, Any], fallback_index: int = 0) -> str:
    """Return the best available ID for a finding, ensuring uniqueness."""
    rid = finding.get("rule_id")
    if isinstance(rid, str) and rid.strip():
        return rid.strip()
    fid = finding.get("id")
    if isinstance(fid, str) and fid.strip():
        return fid.strip()
    # Generate a unique fallback
    return f"UNKNOWN-{fallback_index}"


def export_sarif(
    findings: list[dict[str, Any]], output_file: str = "report.sarif"
) -> None:
    try:
        safe_path = resolve_safe_path(output_file)
        # Ensure parent directory exists
        safe_path.parent.mkdir(parents=True, exist_ok=True)

        rules: dict[str, Any] = {}
        results: list[dict[str, Any]] = []
        unknown_counter = 0

        for _idx, f in enumerate(findings):
            rule_id = _best_id(f, unknown_counter)
            if rule_id.startswith("UNKNOWN-"):
                unknown_counter += 1

            if rule_id not in rules:
                title = redact_sensitive(str(f.get("title", "No Title")))
                description = redact_sensitive(str(f.get("description", "No Description")))
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": description},
                }

            raw_target = redact_sensitive(str(f.get("target", "unknown")))
            safe_uri = urllib.parse.quote(raw_target, safe="/:")
            safe_line = _safe_int(f.get("line", 1))
            message = redact_sensitive(str(f.get("title", "No Title")))

            results.append({
                "ruleId": rule_id,
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": safe_uri},
                        "region": {"startLine": safe_line},
                    }
                }],
            })

        sarif_data = {
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                "Schemata/sarif-schema-2.1.0.json"
            ),
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Pipeline Sentinel",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }],
        }

        # atomic_write preserves permissions if the destination exists
        with atomic_write(safe_path) as sarif_file:
            json.dump(sarif_data, sarif_file, indent=2)

        logger.success(f"SARIF report successfully exported to {safe_path}")
    except Exception as e:
        logger.error(f"Failed to export SARIF report: {e}")


def export_cyclonedx(
    findings: list[dict[str, Any]], output_file: str = "report.cdx.json"
) -> None:
    try:
        safe_path = resolve_safe_path(output_file)
        safe_path.parent.mkdir(parents=True, exist_ok=True)

        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "UNKNOWN": "info",
        }

        components_dict: dict[str, Any] = {}
        vulnerabilities: list[dict[str, Any]] = []
        unknown_counter = 0

        for _idx, f in enumerate(findings):
            raw_target = redact_sensitive(str(f.get("target", "unknown")))
            target_name = raw_target.split("/")[-1] if "/" in raw_target else raw_target
            safe_target = urllib.parse.quote(raw_target, safe="")
            comp_ref = f"pkg:generic/{urllib.parse.quote(target_name, safe='')}?filepath={safe_target}"

            if comp_ref not in components_dict:
                components_dict[comp_ref] = {
                    "type": "file",
                    "bom-ref": comp_ref,
                    "name": target_name,
                }

            raw_sev = str(f.get("severity", "UNKNOWN")).upper()
            mapped_sev = severity_map.get(raw_sev, "info")

            raw_description = str(f.get("description", ""))
            clean_description = redact_sensitive(raw_description)

            vuln_id = _best_id(f, unknown_counter)
            if vuln_id.startswith("UNKNOWN-"):
                unknown_counter += 1

            vulnerabilities.append({
                "id": vuln_id,
                "description": clean_description,
                "ratings": [
                    {
                        "source": {"name": "Pipeline Sentinel Scanner"},
                        "severity": mapped_sev,
                    }
                ],
                "affects": [{"ref": comp_ref}],
            })

        cdx_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "tools": [{
                    "vendor": "DevSecOps",
                    "name": "Pipeline Sentinel",
                }],
            },
            "components": list(components_dict.values()),
            "vulnerabilities": vulnerabilities,
        }

        with atomic_write(safe_path) as cdx_file:
            json.dump(cdx_data, cdx_file, indent=2)

        logger.success(f"CycloneDX report successfully exported to {safe_path}")
    except Exception as e:
        logger.error(f"Failed to export CycloneDX report: {e}")
