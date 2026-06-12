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
        safe_target = self._validate_target_path(target)
        if not safe_target:
            return []

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            outfile = Path(tmp.name)

        try:
            cmd = [
                self.binary_path,
                "detect",
                "--source", safe_target,
                "--report-format", "json",
                "--report-path", str(outfile),
                "--no-git",
            ]

            result = self._safe_run_command(cmd)
            if result.returncode not in (0, 1):
                logger.error(
                    f"Gitleaks exited with unexpected code "
                    f"{result.returncode}: {result.stderr[:300]}"
                )
                return []

            return self.parse(str(outfile))

        except Exception as e:
            logger.error(f"Gitleaks scan failed: {e}")
            return []
        finally:
            if outfile.exists():
                try:
                    outfile.unlink()
                except OSError as e:
                    logger.warning(
                        f"Could not delete temporary file {outfile}: {e}"
                    )

    def parse(self, file_path: str) -> list[ScannerFinding]:
        safe_path = self._validate_target_path(file_path)
        if not safe_path:
            return []

        path = Path(safe_path)
        if not path.exists() or not path.is_file():
            logger.error(f"Gitleaks report not found: {file_path}")
            return []

        try:
            if path.stat().st_size > 50 * 1024 * 1024:
                logger.error(f"Report file {path.name} is too large. Skipping.")
                return []
        except OSError as e:
            logger.error(f"Cannot stat file {path}: {e}")
            return []

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Could not parse Gitleaks output: {e}")
            return []

        if isinstance(data, list):
            raw_findings = data
        elif isinstance(data, dict):
            raw_findings = data.get("Findings", [])
        else:
            logger.warning("Unexpected Gitleaks output format.")
            return []

        findings: list[ScannerFinding] = []
        for item in raw_findings:
            if not isinstance(item, dict):
                continue

            item.get("Match") or item.get("secret") or ""
            description = (
                f"Secret detected (type: {item.get('RuleID', 'unknown')}). "
                "Content has been redacted."
            )
            findings.append({
                "tool": self.name,
                "target": str(item.get("File", item.get("file", ""))),
                "id": str(item.get("RuleID", item.get("ruleID", ""))),
                "severity": "CRITICAL",
                "title": str(item.get("Description", item.get("description", "Secret detected"))),
                "description": description,
                "line": item.get("StartLine") or item.get("line"),
            })

        return findings
