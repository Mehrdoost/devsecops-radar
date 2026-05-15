import json
import subprocess
import tempfile
import os
from typing import List, Dict, Any
from devsecops_radar.plugins import ScannerPlugin

class ZizmorScanner(ScannerPlugin):
    name = "zizmor"
    version = "1.0.0"

    def run(self, target: str) -> List[Dict[str, Any]]:
        if any(c in target for c in [';', '|', '&', '`', '$', '\n', '\r']):
            raise ValueError("Target contains invalid characters.")
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            outfile = tmp.name
        try:
            subprocess.run(
                ['zizmor', 'scan', target, '--output', outfile, '--format', 'json'],
                check=True
            )
            return self.parse(outfile)
        finally:
            if os.path.exists(outfile):
                os.unlink(outfile)

    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        with open(file_path) as f:
            data = json.load(f)
        findings = []
        for result in data.get("findings", []):
            findings.append({
                "tool": "Zizmor",
                "target": result.get("path", ""),
                "id": result.get("rule_id", ""),
                "severity": result.get("severity", "UNKNOWN").upper(),
                "title": result.get("message", ""),
                "description": result.get("description", ""),
                "line": result.get("location", {}).get("line", 0)
            })
        return findings