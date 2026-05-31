import json
import os
import shlex
import subprocess
import tempfile
from typing import Any

from loguru import logger

from devsecops_radar.plugins import ScannerPlugin


class GitleaksScanner(ScannerPlugin):
    name = "gitleaks"
    version = "1.0.0"

    def run(self, target: str) -> list[dict[str, Any]]:
        if not all(c.isalnum() or c in ':/.-_' for c in target):
            raise ValueError("Target contains invalid characters.")
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            outfile = tmp.name
        try:
            cmd = ['gitleaks', 'detect', '--source', target, '--report-format', 'json', '--report-path', outfile]
            logger.info(f"Running: {' '.join(shlex.quote(c) for c in cmd)}")
            subprocess.run(cmd, check=True)
            return self.parse(outfile)
        except subprocess.CalledProcessError as e:
            logger.error(f"Gitleaks scan failed: {e}")
            return []
        finally:
            if os.path.exists(outfile):
                os.unlink(outfile)

    def parse(self, file_path: str) -> list[dict[str, Any]]:
        try:
            with open(file_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Could not parse Gitleaks output: {e}")
            return []
        findings = []
        for item in data if isinstance(data, list) else data.get("Findings", []):
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
