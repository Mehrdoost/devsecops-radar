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

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            outfile = Path(tmp.name)

        try:
            # 2. Secure command construction (no shell=True)
            cmd = [
                self.binary_path,
                "--config=auto",
                "--json",
                "--output", str(outfile),
                safe_target,
            ]

            # 3. Execution with built-in timeouts
            result = self._safe_run_command(cmd)

            # Semgrep returns non-zero if findings exist – that's expected
            if result.returncode not in (0, 1):
                logger.error(
                    f"Semgrep exited with unexpected code "
                    f"{result.returncode}: {result.stderr[:300]}"
                )
                return []

            return self.parse(str(outfile))

        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
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
        # 1. Path safety validation (prevent Path Traversal)
        safe_path = self._validate_target_path(file_path)
        if not safe_path:
            return []

        path = Path(safe_path)

        if not path.exists() or not path.is_file():
            logger.error(f"Semgrep report not found: {file_path}")
            return []

        # 2. Memory protection (50MB limit)
        try:
            if path.stat().st_size > 50 * 1024 * 1024:
                logger.error(
                    f"Semgrep report {path.name} is too large. Skipping."
                )
                return []
        except OSError as e:
            logger.error(f"Cannot stat file {path}: {e}")
            return []

        # 3. Parse JSON safely
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Could not parse Semgrep output: {e}")
            return []

        # 4. Standardize Semgrep severity to system standards
        semgrep_severity_map = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
        }

        findings: list[ScannerFinding] = []
        for result in data.get("results", []):
            if not isinstance(result, dict):
                continue

            raw_severity = str(
                result.get("extra", {}).get("severity", "WARNING")
            ).upper()
            normalized_severity = semgrep_severity_map.get(
                raw_severity, "MEDIUM"
            )

            findings.append({
                "tool": self.name,
                "target": result.get("path", ""),
                "id": result.get("check_id", ""),
                "severity": normalized_severity,
                "title": result.get("check_id", ""),
                "description": result.get("extra", {}).get("message", ""),
                "line": result.get("start", {}).get("line"),
            })

        return findings
