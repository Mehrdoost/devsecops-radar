import json
import os
import tempfile

from devsecops_radar.scanners.gitleaks import GitleaksScanner
from devsecops_radar.scanners.poutine import PoutineScanner
from devsecops_radar.scanners.semgrep import SemgrepScanner
from devsecops_radar.scanners.trivy import TrivyScanner
from devsecops_radar.scanners.zizmor import ZizmorScanner


def write_temp_json(data):
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(data, tmp)
    tmp.close()
    return tmp.name


class TestTrivyScanner:
    def test_valid_json(self):
        data = {
            "Results": [
                {
                    "Target": "img",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-1", "Severity": "HIGH"}
                    ]
                }
            ]
        }
        path = write_temp_json(data)
        findings = TrivyScanner().parse(path)
        os.unlink(path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not json")
            path = f.name
        findings = TrivyScanner().parse(path)
        os.unlink(path)
        assert findings == []

    def test_missing_results(self):
        data = {"not_results": []}
        path = write_temp_json(data)
        findings = TrivyScanner().parse(path)
        os.unlink(path)
        assert findings == []


class TestSemgrepScanner:
    def test_valid(self):
        data = {
            "results": [
                {
                    "path": "a.py",
                    "check_id": "x",
                    "extra": {"severity": "ERROR", "message": "bad"},
                }
            ]
        }
        path = write_temp_json(data)
        findings = SemgrepScanner().parse(path)
        os.unlink(path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "ERROR"

    def test_invalid(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid")
            path = f.name
        findings = SemgrepScanner().parse(path)
        os.unlink(path)
        assert findings == []


class TestPoutineScanner:
    def test_valid(self):
        data = {
            "findings": [
                {
                    "rule_id": "x",
                    "severity": "HIGH",
                    "message": "bad",
                    "location": {"file": "f", "line": 1},
                }
            ]
        }
        path = write_temp_json(data)
        findings = PoutineScanner().parse(path)
        os.unlink(path)
        assert findings[0]["severity"] == "HIGH"


class TestZizmorScanner:
    def test_valid(self):
        data = {
            "findings": [
                {
                    "rule_id": "z1",
                    "severity": "LOW",
                    "message": "m",
                    "path": "p",
                    "location": {"line": 2},
                }
            ]
        }
        path = write_temp_json(data)
        findings = ZizmorScanner().parse(path)
        os.unlink(path)
        assert findings[0]["severity"] == "LOW"


class TestGitleaksScanner:
    def test_valid_list(self):
        data = [{"file": "f", "ruleID": "r", "description": "d", "line": 1}]
        path = write_temp_json(data)
        findings = GitleaksScanner().parse(path)
        os.unlink(path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        