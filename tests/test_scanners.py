import json
import tempfile
import os
from devsecops_radar.scanners.trivy import TrivyScanner
from devsecops_radar.scanners.semgrep import SemgrepScanner
from devsecops_radar.scanners.poutine import PoutineScanner

sample_trivy = {
    "Results": [{
        "Target": "test-app",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-TEST-1",
            "Severity": "CRITICAL",
            "Title": "Test vuln",
            "Description": "Test description",
            "PkgName": "test-pkg",
            "InstalledVersion": "1.0",
            "FixedVersion": "2.0"
        }]
    }]
}

sample_semgrep = {
    "results": [{
        "path": "test.py",
        "check_id": "test.rule",
        "extra": {"severity": "HIGH", "message": "Test finding"},
        "start": {"line": 10}
    }]
}

sample_poutine = {
    "findings": [{
        "rule_id": "test-rule",
        "severity": "MEDIUM",
        "message": "Test poutine",
        "description": "Desc",
        "location": {"file": ".gitlab-ci.yml", "line": 1}
    }]
}

def write_temp(data):
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(data, tmp)
    tmp.close()
    return tmp.name

def test_trivy_parse():
    path = write_temp(sample_trivy)
    findings = TrivyScanner().parse(path)
    os.unlink(path)
    assert len(findings) == 1
    assert findings[0]['tool'] == 'Trivy'
    assert findings[0]['severity'] == 'CRITICAL'

def test_semgrep_parse():
    path = write_temp(sample_semgrep)
    findings = SemgrepScanner().parse(path)
    os.unlink(path)
    assert len(findings) == 1
    assert findings[0]['tool'] == 'Semgrep'
    assert findings[0]['severity'] == 'HIGH'

def test_poutine_parse():
    path = write_temp(sample_poutine)
    findings = PoutineScanner().parse(path)
    os.unlink(path)
    assert len(findings) == 1
    assert findings[0]['tool'] == 'Poutine'
    assert findings[0]['severity'] == 'MEDIUM'