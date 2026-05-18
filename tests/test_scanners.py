import json
import tempfile
import os
from devsecops_radar.scanners.trivy import TrivyScanner

def test_trivy_parse():
    scanner = TrivyScanner()
    data = {
        "Results": [{
            "Target": "test-image",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-0001",
                "Severity": "HIGH",
                "Title": "Test vuln",
                "Description": "Test"
            }]
        }]
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(data, f)
        f.flush()
        findings = scanner.parse(f.name)
    os.unlink(f.name)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["id"] == "CVE-2026-0001"