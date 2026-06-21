# devsecops_radar/scanners/poutine.py
import json
import os
import tempfile
from pathlib import Path
from typing import cast

from loguru import logger

from devsecops_radar.core.path_security import safe_read_open
from devsecops_radar.scanners.base import BaseScanner, ScannerFinding


class PoutineScanner(BaseScanner):
    name = "poutine"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "poutine"

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
            logger.error(
                f"Cannot create temporary file in {self.allowed_base_dir}: {e}"
            )
            return []

        try:
            cmd = [
                self.binary_path,
                "scan",
                safe_target,
                "--format", "json",
                "--output", str(outfile),
            ]

            result = self._safe_run_command(cmd)

            if result.returncode != 0:
                logger.error(
                    f"Poutine exited with code {result.returncode}: "
                    f"{result.stderr[:300]}"
                )
                return []

            findings = self.parse(str(outfile))
            return self._validate_findings(cast(list[dict], findings))  # type: ignore[return-value]

        except Exception as e:
            logger.error(f"Poutine scan failed: {e}")
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
            f = safe_read_open(file_path, base_dir=self.allowed_base_dir)
        except ValueError as e:
            logger.error(f"Security or file error: {e}")
            return []
        except (FileNotFoundError, PermissionError, OSError) as e:
            logger.error(f"Could not read Poutine report: {e}")
            return []

        with f:
            try:
                stat = os.fstat(f.fileno())
                if stat.st_size > 50 * 1024 * 1024:
                    logger.error(
                        f"Poutine report too large ({stat.st_size} bytes). Skipping."
                    )
                    return []
            except OSError as e:
                logger.error(f"Cannot stat report: {e}")
                return []

            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Could not parse Poutine output: {e}")
                return []

        findings: list[ScannerFinding] = []
        for result in data.get("findings", []):
            if not isinstance(result, dict):
                continue

            loc = result.get("location", {})
            if not isinstance(loc, dict):
                loc = {}

            findings.append({
                "tool": self.name,
                "target": loc.get("file", ""),
                "id": result.get("rule_id", ""),
                "severity": str(result.get("severity", "UNKNOWN")).upper(),
                "title": result.get("message", ""),
                "description": result.get("description", ""),
                "line": loc.get("line"),
            })

        return findings
