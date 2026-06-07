import json
import tempfile
from pathlib import Path

from loguru import logger

from devsecops_radar.scanners.base import BaseScanner, ScannerFinding


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "semgrep"

    def run(self, target: str) -> list[ScannerFinding]:
        # 1. Strict and secure path validation
        safe_target = self._validate_target_path(target)
        if not safe_target:
            return []

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            outfile = Path(tmp.name)

        try:
            # 2. Secure command construction (no shell=True)
            cmd = [
                self.binary_path,
                '--config=auto',
                '--json',
                '--output', str(outfile),
                safe_target
            ]

            # 3. Secure execution with Timeout protection
            # Semgrep may return non-zero exit code if vulnerabilities are found,
            # Parent class sets check=False to only raise errors on actual crashes.
            self._safe_run_command(cmd)
            return self.parse(str(outfile))

        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
            return []
        finally:
            if outfile.exists():
                outfile.unlink()

    def parse(self, file_path: str) -> list[ScannerFinding]:
        path = Path(file_path)

        if not path.exists() or not path.is_file():
            return []

        # 4. Memory protection (50MB limit)
        if path.stat().st_size > 50 * 1024 * 1024:
            logger.error(f"Semgrep report {path.name} is too large. Skipping.")
            return []

        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Could not parse Semgrep output: {e}")
            return []

        # 5. Standardize Semgrep severity to system standards
        semgrep_severity_map = {
            "ERROR": "HIGH",     # In Semgrep, ERRORs are usually high risk
            "WARNING": "MEDIUM",
            "INFO": "LOW"
        }

        findings: list[ScannerFinding] = []
        for result in data.get("results", []):
            if not isinstance(result, dict):
                continue

            raw_severity = str(result.get("extra", {}).get("severity", "WARNING")).upper()
            normalized_severity = semgrep_severity_map.get(raw_severity, "MEDIUM")

            findings.append({
                "tool": self.name,
                "target": result.get("path", ""),
                "id": result.get("check_id", ""),
                "severity": normalized_severity,
                "title": result.get("check_id", ""),
                "description": result.get("extra", {}).get("message", ""),
                "line": result.get("start", {}).get("line", 0)
            })

        return findings
