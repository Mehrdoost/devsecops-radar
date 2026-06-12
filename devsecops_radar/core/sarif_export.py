import json
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger


def _get_safe_path(output_file: str, allowed_dir: str = ".") -> Path:
    """Ensures the export file is written in a safe, allowed location."""
    base_path = Path(allowed_dir).resolve()
    target_path = (base_path / output_file).resolve()

    if not target_path.is_relative_to(base_path):
        raise ValueError(
            f"Security Violation: Path traversal attempt detected in "
            f"'{output_file}'"
        )
    return target_path


def _safe_int(val: Any, default: int = 1) -> int:
    """Ensures the line number is a valid positive integer for standard compliance."""
    try:
        res = int(val)
        return res if res > 0 else default
    except (ValueError, TypeError):
        return default


def export_sarif(
    findings: list[dict[str, Any]], output_file: str = "report.sarif"
) -> None:
    """Exports findings to SARIF 2.1.0 standard with strict validation."""
    try:
        safe_path = _get_safe_path(output_file)
        rules = {}
        results = []

        for f in findings:
            rule_id = str(f.get("id", "UNKNOWN"))
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": str(f.get("title", "No Title"))
                    },
                    "fullDescription": {
                        "text": str(f.get("description", "No Description"))
                    },
                }

            # Prevent URI Injection in consumers of this SARIF file
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

        with open(safe_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)

        logger.success(f"SARIF report successfully exported to {safe_path}")
    except Exception as e:
        logger.error(f"Failed to export SARIF report: {e}")


def export_cyclonedx(
    findings: list[dict[str, Any]], output_file: str = "report.cdx.json"
) -> None:
    """Exports findings to a strictly compliant CycloneDX 1.5 format."""
    try:
        safe_path = _get_safe_path(output_file)

        # Standard CycloneDX severity capitalization
        severity_map = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "UNKNOWN": "Info",
        }

        components_dict = {}
        vulnerabilities = []

        for f in findings:
            raw_target = str(f.get("target", "unknown"))
            # Use path-safe encoding for URI but keep structure readable
            safe_target = urllib.parse.quote(raw_target, safe="/:")
            comp_ref = f"pkg:file/{safe_target}"

            if comp_ref not in components_dict:
                components_dict[comp_ref] = {
                    "type": "file",
                    "bom-ref": comp_ref,
                    "name": raw_target,
                }

            raw_sev = str(f.get("severity", "UNKNOWN")).upper()
            mapped_sev = severity_map.get(raw_sev, "Info")

            vulnerabilities.append({
                "id": str(f.get("id", "UNKNOWN")),
                "description": str(f.get("description", "")),
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
                # ISO8601 UTC timestamp (using timezone-aware)
                "timestamp": datetime.now(UTC).isoformat(),
                "tools": [{
                    "vendor": "DevSecOps",
                    "name": "Pipeline Sentinel",
                }],
            },
            "components": list(components_dict.values()),
            "vulnerabilities": vulnerabilities,
        }

        with open(safe_path, "w", encoding="utf-8") as f:
            json.dump(cdx_data, f, indent=2)

        logger.success(
            f"CycloneDX report successfully exported to {safe_path}"
        )
    except Exception as e:
        logger.error(f"Failed to export CycloneDX report: {e}")
