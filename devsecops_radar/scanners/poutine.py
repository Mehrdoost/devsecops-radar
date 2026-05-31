import json
import os
import shlex
import subprocess
import tempfile
from typing import Any

from loguru import logger

from devsecops_radar.plugins import ScannerPlugin


class PoutineScanner(ScannerPlugin):
    name = "poutine"
    version = "1.0.0"

    def run(self, target: str) -> list[dict[str, Any]]:
        if not all(c.isalnum() or c in ':/.-_' for c in target):
            raise ValueError("Target contains invalid characters.")
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            outfile = tmp.name
        try:
            cmd = ['poutine', 'scan', target, '--format', 'json', '--output', outfile]
            logger.info(f"Running: {' '.join(shlex.quote(c) for c in cmd)}")
            subprocess.run(cmd, check=True)
            return self.parse(outfile)
        except subprocess.CalledProcessError as e:
            logger.error(f"Poutine scan failed: {e}")
            return []
        finally:
            if os.path.exists(outfile):
                os.unlink(outfile)

    def parse(self, file_path: str) -> list[dict[str, Any]]:
        try:
            with open(file_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Could not parse Poutine output: {e}")
            return []
        findings = []
        for result in data.get("findings", []):
            findings.append({
                "tool": "Poutine",
                "target": result.get("location", {}).get("file", ""),
                "id": result.get("rule_id", ""),
                "severity": (result.get("severity", "UNKNOWN") or "UNKNOWN").upper(),
                "title": result.get("message", ""),
                "description": result.get("description", ""),
                "line": result.get("location", {}).get("line", 0)
            })
        return findings
