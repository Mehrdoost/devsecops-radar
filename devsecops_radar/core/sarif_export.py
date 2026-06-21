# devsecops_radar/core/sarif_export.py
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


def export_sarif(
    findings: list[dict[str, Any]], output_file: str = "report.sarif"
) -> None:
    try:
        safe_path = resolve_safe_path(output_file)

        rules: dict[str, Any] = {}
        results: list[dict[str, Any]] = []

        for f in findings:
            rule_id = str(f.get("id", "UNKNOWN"))
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": str(f.get("title", "No Title"))},
                    "fullDescription": {"text": str(f.get("description", "No Description"))},
                }

            raw_target = str(f.get("target", "unknown"))
            safe_uri = urllib.parse.quote(raw_target, safe="/:")
            safe_line = _safe_int(f.get("line", 1))

            results.append({
                "ruleId": rule_id,
                "message": {"text": str(f.get("title", "No Title"))},
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

        # Correct CycloneDX severity format (lowercase)
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "UNKNOWN": "info",
        }

        components_dict: dict[str, Any] = {}
        vulnerabilities: list[dict[str, Any]] = []

        for f in findings:
            raw_target = str(f.get("target", "unknown"))
            safe_target = urllib.parse.quote(raw_target, safe="/:")
            comp_ref = f"pkg:file/{safe_target}"

            if comp_ref not in components_dict:
                components_dict[comp_ref] = {
                    "type": "file",
                    "bom-ref": comp_ref,
                    "name": raw_target,
                }

            raw_sev = str(f.get("severity", "UNKNOWN")).upper()
            mapped_sev = severity_map.get(raw_sev, "info")

            # Redact sensitive data from descriptions
            raw_description = str(f.get("description", ""))
            clean_description = redact_sensitive(raw_description)

            vulnerabilities.append({
                "id": str(f.get("id", "UNKNOWN")),
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
