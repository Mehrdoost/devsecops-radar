import json
from typing import Any


def export_sarif(findings: list[dict[str, Any]], output_file: str = "report.sarif") -> None:
    rules = {}
    results = []
    for f in findings:
        rule_id = f.get("id", "UNKNOWN")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f.get("title", "")},
                "fullDescription": {"text": f.get("description", "")},
                "help": {"text": f.get("description", "")}
            }
        results.append({
            "ruleId": rule_id,
            "message": {"text": f.get("title", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("target", "")},
                    "region": {"startLine": f.get("line", 1)}
                }
            }]
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Pipeline Sentinel",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }]
    }
    with open(output_file, 'w') as f:
        json.dump(sarif, f, indent=2)


def export_cyclonedx(findings: list[dict[str, Any]], output_file: str = "report.cdx.json") -> None:
    vulnerabilities = []
    for f in findings:
        vulnerabilities.append({
            "id": f.get("id", ""),
            "description": f.get("description", ""),
            "recommendation": "",
            "severity": f.get("severity", "").lower(),
            "affects": [{"ref": f.get("target", "")}]
        })

    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "vulnerabilities": vulnerabilities
    }
    with open(output_file, 'w') as f:
        json.dump(cdx, f, indent=2)
