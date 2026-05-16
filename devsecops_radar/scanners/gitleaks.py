import json
import subprocess
import tempfile
import os
from typing import List, Dict, Any
from devsecops_radar.plugins import ScannerPlugin

class GitleaksScanner(ScannerPlugin):
    name = "gitleaks"
    version = "1.0.0"

    def run(self, target: str) -> List[Dict[str, Any]]:
        if any(c in target for c in [';', '|', '&', '`', '$', '\n', '\r']):
            raise ValueError("Target contains invalid characters.")
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            outfile = tmp.name
        try:
            subprocess.run(['gitleaks', 'detect', '--source', target, '--report-format', 'json', '--report-path', outfile], check=True)
            return self.parse(outfile)
        finally:
            if os.path.exists(outfile):
                os.unlink(outfile)

    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        with open(file_path) as f:
            data = json.load(f)
        findings = []
        for item in data:
            findings.append({
                "tool": "Gitleaks",
                "target": item.get("file", ""),
                "id": item.get("ruleID", ""),
                "severity": "HIGH",
                "title": item.get("description", "Secret detected"),
                "description": f"Secret found: {item.get('secret', '')}",
                "line": item.get("line", 0)
            })
        return findings