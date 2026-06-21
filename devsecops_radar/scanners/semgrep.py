# devsecops_radar/scanners/semgrep.py
import json
import os
import tempfile
from pathlib import Path
from typing import cast

from loguru import logger

from devsecops_radar.core.path_security import safe_read_open
from devsecops_radar.scanners.base import BaseScanner, ScannerFinding


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "semgrep"

    def run(self, target: str) -> list[ScannerFinding]:
        safe_target = self._validate_target_path(target)
        if not safe_target:
            return []

        try:
            tmp_fd, tmp_path = tempfile.mkstemp(
                suffix=".json", dir=str(self.allowed_base_dir)
            )
            os.close(tmp_fd)
            outfile = Path(tmp_path)
        except OSError as e:
            logger.error(f"Cannot create temporary file in {self.allowed_base_dir}: {e}")
            return []

        try:
            cmd = [
                self.binary_path,
                "--config=auto",
                "--json",
                "--output", str(outfile),
                safe_target,
            ]

            result = self._safe_run_command(cmd)

            if result.returncode not in (0, 1):
                logger.error(
                    f"Semgrep exited with unexpected code "
                    f"{result.returncode}: {result.stderr[:300]}"
                )
                return []

            findings = self.parse(str(outfile))
            return self._validate_findings(cast(list[dict], findings))  # type: ignore[return-value]

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
        try:
            with safe_read_open(file_path, base_dir=self.allowed_base_dir) as f:
                try:
                    stat = os.fstat(f.fileno())
                    if stat.st_size > 50 * 1024 * 1024:
                        logger.error(f"Report file too large ({stat.st_size} bytes). Skipping.")
                        return []
                except OSError as e:
                    logger.error(f"Cannot stat report: {e}")
                    return []
                data = json.load(f)
        except ValueError as e:
            logger.error(f"Security or file error: {e}")
            return []
        except (json.JSONDecodeError, FileNotFoundError, PermissionError, OSError) as e:
            logger.error(f"Could not read or parse Semgrep report: {e}")
            return []

        semgrep_severity_map = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
        }

        findings: list[ScannerFinding] = []
        for result in data.get("results", []):
            if not isinstance(result, dict):
                continue

            extra = result.get("extra")
            if not isinstance(extra, dict):
                extra = {}

            raw_severity = str(extra.get("severity", "WARNING")).upper()
            normalized_severity = semgrep_severity_map.get(
                raw_severity, "MEDIUM"
            )

            findings.append({
                "tool": self.name,
                "target": result.get("path", ""),
                "id": result.get("check_id", ""),
                "severity": normalized_severity,
                "title": result.get("check_id", ""),
                "description": extra.get("message", ""),
                "line": result.get("start", {}).get("line"),
            })

        return findings
