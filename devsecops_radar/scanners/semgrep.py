import json
import os
import shlex
import subprocess
import tempfile
from typing import Any

from loguru import logger

from devsecops_radar.plugins import ScannerPlugin


class SemgrepScanner(ScannerPlugin):
    name = "semgrep"
    version = "1.0.0"

    def run(self, target: str) -> list[dict[str, Any]]:
        if not all(c.isalnum() or c in ':/.-_' for c in target):
            raise ValueError("Target contains invalid characters.")
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            outfile = tmp.name
        try:
            cmd = ['semgrep', '--config=auto', '--json', '--output', outfile, target]
            logger.info(f"Running: {' '.join(shlex.quote(c) for c in cmd)}")
            subprocess.run(cmd, check=True)
            return self.parse(outfile)
        except subprocess.CalledProcessError as e:
            logger.error(f"Semgrep scan failed: {e}")
            return []
        finally:
            if os.path.exists(outfile):
                os.unlink(outfile)

    def parse(self, file_path: str) -> list[dict[str, Any]]:
        try:
            with open(file_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Could not parse Semgrep output: {e}")
            return []
        findings = []
        for result in data.get("results", []):
            findings.append({
                "tool": "Semgrep",
                "target": result.get("path", ""),
                "id": result.get("check_id", ""),
                "severity": (result.get("extra", {}).get("severity", "WARNING") or "WARNING").upper(),
                "title": result.get("check_id", ""),
                "description": result.get("extra", {}).get("message", ""),
                "line": result.get("start", {}).get("line", 0)
            })
        return findings
