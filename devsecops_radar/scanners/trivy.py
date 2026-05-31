import json
import os
import shlex
import subprocess
import tempfile
from typing import Any

from loguru import logger

from devsecops_radar.plugins import ScannerPlugin


class TrivyScanner(ScannerPlugin):
    name = "trivy"
    version = "1.0.0"

    def run(self, target: str) -> list[dict[str, Any]]:
        if not all(c.isalnum() or c in ':/.-_' for c in target):
            raise ValueError("Target contains invalid characters.")
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            outfile = tmp.name
        try:
            cmd = ['trivy', 'image', '--format', 'json', '--output', outfile, target]
            logger.info(f"Running: {' '.join(shlex.quote(c) for c in cmd)}")
            subprocess.run(cmd, check=True)
            return self.parse(outfile)
        except subprocess.CalledProcessError as e:
            logger.error(f"Trivy scan failed: {e}")
            return []
        finally:
            if os.path.exists(outfile):
                os.unlink(outfile)

    def parse(self, file_path: str) -> list[dict[str, Any]]:
        try:
            with open(file_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Could not parse Trivy output: {e}")
            return []
        findings = []
        for result in data.get("Results", []):
            target_name = result.get("Target", "Unknown")
            for vuln in result.get("Vulnerabilities", []):
                findings.append({
                    "tool": "Trivy",
                    "target": target_name,
                    "id": vuln.get("VulnerabilityID", ""),
                    "severity": (vuln.get("Severity", "UNKNOWN") or "UNKNOWN").upper(),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", "")
                })
        return findings
