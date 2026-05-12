import json
import subprocess
import tempfile
import os
from typing import List, Dict, Any
from .base import BaseScanner

class TrivyScanner(BaseScanner):
    def run(self, target: str) -> List[Dict[str, Any]]:
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            outfile = tmp.name
        try:
            subprocess.run(['trivy', 'image', '--format', 'json', '--output', outfile, target], check=True)
            return self.parse(outfile)
        finally:
            if os.path.exists(outfile):
                os.unlink(outfile)

    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        with open(file_path) as f:
            data = json.load(f)
        findings = []
        for result in data.get("Results", []):
            target_name = result.get("Target", "Unknown")
            for vuln in result.get("Vulnerabilities", []):
                findings.append({
                    "tool": "Trivy",
                    "target": target_name,
                    "id": vuln.get("VulnerabilityID"),
                    "severity": vuln.get("Severity", "UNKNOWN").upper(),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", "")
                })
        return findings