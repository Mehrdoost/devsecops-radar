# devsecops_radar/scanners/trivy.py
import json
import os
import re
import tempfile
from pathlib import Path
from typing import cast

from loguru import logger

from devsecops_radar.core.path_security import safe_read_open
from devsecops_radar.scanners.base import BaseScanner, ScannerFinding


class TrivyScanner(BaseScanner):
    name = "trivy"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "trivy"

    def _validate_image_target(self, target: str) -> str:
        target = target.strip()
        if target.startswith("-"):
            logger.error("Security Violation: Target cannot start with a hyphen.")
            return ""
        if not re.match(r"^[a-zA-Z0-9_.:/@-]+$", target):
            logger.error("Security Violation: Target contains invalid characters.")
            return ""
        if target.count("@") > 1:
            logger.error("Security Violation: Target contains multiple '@' characters.")
            return ""
        if "@" in target:
            parts = target.split("@")
            if len(parts) != 2 or not parts[0] or not parts[1]:
                logger.error("Security Violation: Invalid digest format in target.")
                return ""
        return target

    def run(self, target: str) -> list[ScannerFinding]:
        safe_target = self._validate_image_target(target)
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
                "image",
                "--format", "json",
                "--output", str(outfile),
                "--no-progress",
                safe_target,
            ]

            result = self._safe_run_command(cmd)
            if result.returncode != 0:
                logger.error(
                    f"Trivy exited with code {result.returncode}: "
                    f"{result.stderr[:300]}"
                )
                return []

            findings = self.parse(str(outfile))
            return self._validate_findings(cast(list[dict], findings))  # type: ignore[return-value]

        except Exception as e:
            logger.error(f"Trivy scan failed: {e}")
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
                        logger.error(
                            f"Trivy report too large ({stat.st_size} bytes). Skipping."
                        )
                        return []
                except OSError as e:
                    logger.error(f"Cannot stat report: {e}")
                    return []
                data = json.load(f)
        except ValueError as e:
            logger.error(f"Security or file error: {e}")
            return []
        except (json.JSONDecodeError, FileNotFoundError, PermissionError, OSError) as e:
            logger.error(f"Could not read or parse Trivy report: {e}")
            return []

        findings: list[ScannerFinding] = []
        for result in data.get("Results", []):
            if not isinstance(result, dict):
                continue

            target_name = result.get("Target", "Unknown")
            for vuln in result.get("Vulnerabilities", []):
                if not isinstance(vuln, dict):
                    continue

                pkg_name = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                base_desc = vuln.get("Description", "")

                enriched_desc = (
                    f"{base_desc}\n\n"
                    f"Package: {pkg_name} ({installed})\n"
                    f"Fixed Version: {fixed}"
                ).strip()

                findings.append({
                    "tool": self.name,
                    "target": target_name,
                    "id": vuln.get("VulnerabilityID", ""),
                    "severity": str(vuln.get("Severity", "UNKNOWN")).upper(),
                    "title": vuln.get("Title", ""),
                    "description": enriched_desc,
                    "line": None,
                })

        return findings
