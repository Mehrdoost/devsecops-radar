import json
import tempfile
from pathlib import Path

from loguru import logger

from devsecops_radar.scanners.base import BaseScanner, ScannerFinding


class GitleaksScanner(BaseScanner):
    name = "gitleaks"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "gitleaks"

    def run(self, target: str) -> list[ScannerFinding]:
        # 1. Strict path validation (replaces insecure regex)
        safe_target = self._validate_target_path(target)
        if not safe_target:
            return []

        # Use pathlib for clean temporary file management
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            outfile = Path(tmp.name)

        try:
            # 2. Secure command construction (no shell=True)
            cmd = [
                self.binary_path,
                "detect",
                "--source", safe_target,
                "--report-format", "json",
                "--report-path", str(outfile),
                "--no-git"
            ]

            # 3. Secure execution with Timeout (handled in parent class)
            self._safe_run_command(cmd)
            return self.parse(str(outfile))

        except Exception as e:
            logger.error(f"Gitleaks scan failed: {e}")
            return []
        finally:
            if outfile.exists():
                outfile.unlink()

    def parse(self, file_path: str) -> list[ScannerFinding]:
        path = Path(file_path)

        if not path.exists() or not path.is_file():
            return []

        # 4. Prevent Memory DoS (skip files > 50MB)
        if path.stat().st_size > 50 * 1024 * 1024:
            logger.error(f"Report file {path.name} is too large. Skipping.")
            return []

        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Could not parse Gitleaks output: {e}")
            return []

        # 5. Smart parsing and standardized output
        raw_findings = data if isinstance(data, list) else data.get("Findings", [])
        findings: list[ScannerFinding] = []

        for item in raw_findings:
            if not isinstance(item, dict):
                continue

            findings.append({
                "tool": self.name,
                "target": item.get("File", item.get("file", "")),
                "id": item.get("RuleID", item.get("ruleID", "")),
                "severity": "CRITICAL",  # Leaked secrets are always critical
                "title": item.get("Description", item.get("description", "Secret detected")),
                "description": f"Secret found: {item.get('Match', item.get('secret', '***'))}",
                "line": item.get("StartLine", item.get("line", 0))
            })

        return findings
