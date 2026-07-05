# devsecops_radar/scanners/poutine.py
"""
Poutine scanner – GitLab CI/CD pipeline security analysis.
"""

from __future__ import annotations

import json
from typing import Any

from loguru import logger

from devsecops_radar.scanners.base import BaseScanner


class PoutineScanner(BaseScanner):
    name = "poutine"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "poutine"

    def _run_internal(self, safe_target: str) -> list[dict[str, Any]]:
        cmd = [
            self.binary_path,
            "scan",
            safe_target,
            "--format", "json",
            "--output", "-",
        ]

        result = self._safe_run_command(cmd)

        if result.returncode not in (0, 1):
            logger.error(
                f"Poutine exited with unexpected code {result.returncode}: "
                f"{result.stderr[:300]}"
            )
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Poutine output: {e}")
            return []

        raw_findings = self._parse_results(data)
        return self._validate_findings(raw_findings)

    def _parse_results(self, data: dict) -> list[dict[str, Any]]:
        from devsecops_radar.core.reporting import redact_sensitive

        findings: list[dict[str, Any]] = []
        for result in data.get("findings", []):
            if not isinstance(result, dict):
                continue

            loc = result.get("location", {})
            if not isinstance(loc, dict):
                loc = {}

            rule_id = result.get("rule_id", "")
            if not rule_id or not rule_id.strip():
                logger.debug("Skipping Poutine finding with empty rule_id.")
                continue

            message = result.get("message", "")
            if not message or not message.strip():
                logger.debug("Skipping Poutine finding with empty message.")
                continue

            findings.append({
                "tool": self.name,
                "target": loc.get("file", ""),
                "id": rule_id,
                "severity": str(result.get("severity", "UNKNOWN")).upper(),
                "title": message,
                "description": redact_sensitive(result.get("description", "")),
                "line": loc.get("line"),
            })

        return findings

    def parse(self, file_path: str) -> list[dict[str, Any]]:
        from devsecops_radar.core.path_security import safe_read_open
        try:
            with safe_read_open(file_path, base_dir=self.allowed_base_dir) as f:
                data = json.load(f)
        except (ValueError, FileNotFoundError, PermissionError, OSError, json.JSONDecodeError) as e:
            logger.error(f"Could not read Poutine report: {e}")
            return []

        return self._parse_results(data)
