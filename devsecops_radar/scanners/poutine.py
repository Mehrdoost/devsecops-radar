import json
import tempfile
from pathlib import Path

from loguru import logger

from devsecops_radar.scanners.base import BaseScanner, ScannerFinding


class PoutineScanner(BaseScanner):
    name = "poutine"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "poutine"

    def run(self, target: str) -> list[ScannerFinding]:
        # 1. Strict path validation to prevent Path Traversal
        safe_target = self._validate_target_path(target)
        if not safe_target:
            return []

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            outfile = Path(tmp.name)

        try:
            # 2. Secure command construction (no shell=True)
            cmd = [
                self.binary_path,
                'scan',
                safe_target,
                '--format', 'json',
                '--output', str(outfile)
            ]

            # 3. Execution handled by the parent class with built-in timeouts
            self._safe_run_command(cmd)
            return self.parse(str(outfile))

        except Exception as e:
            logger.error(f"Poutine scan failed: {e}")
            return []
        finally:
            if outfile.exists():
                outfile.unlink()

    def parse(self, file_path: str) -> list[ScannerFinding]:
        path = Path(file_path)

        if not path.exists() or not path.is_file():
            return []

        # 4. Memory Exhaustion Protection (50MB limit)
        if path.stat().st_size > 50 * 1024 * 1024:
            logger.error(f"Poutine report {path.name} is too large. Skipping.")
            return []

        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Could not parse Poutine output: {e}")
            return []

        findings: list[ScannerFinding] = []
        for result in data.get("findings", []):
            if not isinstance(result, dict):
                continue

            findings.append({
                "tool": self.name,
                "target": result.get("location", {}).get("file", ""),
                "id": result.get("rule_id", ""),
                "severity": str(result.get("severity", "UNKNOWN")).upper(),
                "title": result.get("message", ""),
                "description": result.get("description", ""),
                "line": result.get("location", {}).get("line", 0)
            })

        return findings
