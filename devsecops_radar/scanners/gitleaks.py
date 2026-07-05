# devsecops_radar/scanners/gitleaks.py
"""
Gitleaks scanner – detect hardcoded secrets in repositories.
"""

from __future__ import annotations

import json
from typing import Any

from loguru import logger

from devsecops_radar.scanners.base import BaseScanner


class GitleaksScanner(BaseScanner):
    name = "gitleaks"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "gitleaks"

    def _run_internal(self, safe_target: str) -> list[dict[str, Any]]:
        cmd = [
            self.binary_path,
            "detect",
            "--source", safe_target,
            "--report-format", "json",
            "--report-path", "-",
            "--no-git",
        ]

        result = self._safe_run_command(cmd)

        if result.returncode not in (0, 1):
            logger.error(
                f"Gitleaks exited with unexpected code "
                f"{result.returncode}: {result.stderr[:300]}"
            )
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gitleaks output: {e}")
            return []

        raw_findings = self._parse_results(data)
        return self._validate_findings(raw_findings)

    def _parse_results(self, data: Any) -> list[dict[str, Any]]:
        if isinstance(data, list):
            raw_findings = data
        elif isinstance(data, dict):
            raw_findings = data.get("Findings", [])
        else:
            logger.warning("Unexpected Gitleaks output format.")
            return []

        findings: list[dict[str, Any]] = []
        for item in raw_findings:
            if not isinstance(item, dict):
                continue

            target = str(item.get("File", item.get("file", "")))
            rule_id = str(item.get("RuleID", item.get("ruleID", "")))

            if not rule_id or not rule_id.strip():
                logger.debug("Skipping Gitleaks finding with empty RuleID.")
                continue

            # Redact secret content
            from devsecops_radar.core.reporting import redact_sensitive
            description = f"Secret detected (type: {rule_id}). Content has been redacted."

            findings.append({
                "tool": self.name,
                "target": target,
                "id": rule_id,
                "severity": "CRITICAL",
                "title": str(item.get("Description", item.get("description", "Secret detected"))),
                "description": redact_sensitive(description),
                "line": item.get("StartLine") or item.get("line"),
            })

        return findings

    def parse(self, file_path: str) -> list[dict[str, Any]]:
        from devsecops_radar.core.path_security import safe_read_open
        try:
            with safe_read_open(file_path, base_dir=self.allowed_base_dir) as f:
                data = json.load(f)
        except (ValueError, FileNotFoundError, PermissionError, OSError, json.JSONDecodeError) as e:
            logger.error(f"Could not read Gitleaks report: {e}")
            return []

        return self._parse_results(data)
