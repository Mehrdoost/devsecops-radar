# devsecops_radar/scanners/trivy.py
"""
Trivy scanner – container image & filesystem vulnerability scanning.
"""

from __future__ import annotations

import json
import re
from typing import Any

from loguru import logger

from devsecops_radar.scanners.base import BaseScanner


class TrivyScanner(BaseScanner):
    name = "trivy"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "trivy"

    # ------------------------------------------------------------------
    # Image name validation (only used when target is not a file path)
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Core scan
    # ------------------------------------------------------------------
    def _run_internal(self, safe_target: str) -> list[dict[str, Any]]:
        # Decide whether to use "image" or "filesystem" subcommand
        if any(c in safe_target for c in ("/", "\\")):
            subcommand = "filesystem"
        else:
            safe_target = self._validate_image_target(safe_target)
            if not safe_target:
                return []
            subcommand = "image"

        cmd = [
            self.binary_path,
            subcommand,
            "--format", "json",
            "--output", "-",
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

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Trivy output: {e}")
            return []

        raw_findings = self._parse_results(data)
        return self._validate_findings(raw_findings)

    def _parse_results(self, data: dict) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
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

                # Redact any secrets that may have leaked into descriptions
                from devsecops_radar.core.reporting import redact_sensitive
                enriched_desc = redact_sensitive(
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

    # ------------------------------------------------------------------
    # Parse a pre‑existing report file
    # ------------------------------------------------------------------
    def parse(self, file_path: str) -> list[dict[str, Any]]:
        from devsecops_radar.core.path_security import safe_read_open
        try:
            with safe_read_open(file_path, base_dir=self.allowed_base_dir) as f:
                data = json.load(f)
        except (ValueError, FileNotFoundError, PermissionError, OSError, json.JSONDecodeError) as e:
            logger.error(f"Could not read Trivy report: {e}")
            return []

        return self._parse_results(data)
