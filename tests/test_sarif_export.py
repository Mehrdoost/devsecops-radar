import json
import os
import tempfile

from devsecops_radar.core.sarif_export import export_cyclonedx, export_sarif


def test_export_sarif():
    findings = [
        {
            "id": "CVE-2026-1234",
            "title": "Test vulnerability",
            "description": "A test vulnerability description",
            "target": "src/app.py",
            "line": 42,
        }
    ]
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
        output_file = tmp.name

    try:
        export_sarif(findings, output_file)
        assert os.path.exists(output_file)
        with open(output_file) as f:
            sarif = json.load(f)

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "Pipeline Sentinel"
        assert len(run["results"]) == 1
        result = run["results"][0]
        assert result["ruleId"] == "CVE-2026-1234"
        assert result["message"]["text"] == "Test vulnerability"
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
    finally:
        os.unlink(output_file)


def test_export_sarif_missing_fields():
    findings = [{}]  # finding with no id, title, etc.
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
        output_file = tmp.name

    try:
        export_sarif(findings, output_file)
        with open(output_file) as f:
            sarif = json.load(f)

        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "UNKNOWN"
        assert result["message"]["text"] == ""
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ""
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    finally:
        os.unlink(output_file)


def test_export_cyclonedx():
    findings = [
        {
            "id": "CVE-2026-5678",
            "description": "Another test vuln",
            "severity": "HIGH",
            "target": "lib/thing.jar",
        }
    ]
    with tempfile.NamedTemporaryFile(suffix=".cdx.json", delete=False) as tmp:
        output_file = tmp.name

    try:
        export_cyclonedx(findings, output_file)
        assert os.path.exists(output_file)
        with open(output_file) as f:
            cdx = json.load(f)

        assert cdx["bomFormat"] == "CycloneDX"
        assert cdx["specVersion"] == "1.5"
        assert len(cdx["vulnerabilities"]) == 1
        vuln = cdx["vulnerabilities"][0]
        assert vuln["id"] == "CVE-2026-5678"
        assert vuln["severity"] == "high"  # converted to lower
        assert vuln["affects"][0]["ref"] == "lib/thing.jar"
    finally:
        os.unlink(output_file)


def test_export_cyclonedx_multiple():
    findings = [
        {"id": "A", "description": "a", "severity": "LOW", "target": "x"},
        {"id": "B", "description": "b", "severity": "CRITICAL", "target": "y"},
    ]
    with tempfile.NamedTemporaryFile(suffix=".cdx.json", delete=False) as tmp:
        output_file = tmp.name

    try:
        export_cyclonedx(findings, output_file)
        with open(output_file) as f:
            cdx = json.load(f)
        assert len(cdx["vulnerabilities"]) == 2
    finally:
        os.unlink(output_file)
