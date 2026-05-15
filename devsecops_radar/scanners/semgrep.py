import json
import subprocess
import tempfile
import os
from typing import List, Dict, Any
from .base import BaseScanner


class SemgrepScanner(BaseScanner):
    def run(self, target: str) -> List[Dict[str, Any]]:
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            outfile = tmp.name
        try:
            subprocess.run(
                ['semgrep', '--config=auto', '--json', '--output', outfile, target],
                check=True,
            )
            return self.parse(outfile)
        finally:
            if os.path.exists(outfile):
                os.unlink(outfile)

    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        with open(file_path) as f:
            data = json.load(f)
        findings = []
        for result in data.get("results", []):
            findings.append({
                "tool": "Semgrep",
                "target": result.get("path", ""),
                "id": result.get("check_id", ""),
                "severity": result.get("extra", {}).get("severity", "WARNING").upper(),
                "title": result.get("check_id", ""),
                "description": result.get("extra", {}).get("message", ""),
                "line": result.get("start", {}).get("line", 0),
            })
        return findings