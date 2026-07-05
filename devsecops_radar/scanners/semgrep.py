# devsecops_radar/scanners/semgrep.py
"""
Semgrep scanner – static analysis for code patterns.
"""

from __future__ import annotations

import json
from typing import Any

from loguru import logger

from devsecops_radar.scanners.base import BaseScanner


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "semgrep"

    # ------------------------------------------------------------------
    # Core scan
    # ------------------------------------------------------------------
    def _run_internal(self, safe_target: str) -> list[dict[str, Any]]:
        # Use user‑supplied or bundled rules to stay offline
        cmd = [
            self.binary_path,
            "--config", "auto",   # FIXME: replace with a path to offline rules
            "--json",
            "--output", "-",
            safe_target,
        ]

        result = self._safe_run_command(cmd)

        if result.returncode not in (0, 1):
            logger.error(
                f"Semgrep exited with unexpected code "
                f"{result.returncode}: {result.stderr[:300]}"
            )
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
            return []

        raw_findings = self._parse_results(data)
        return self._validate_findings(raw_findings)

    def _parse_results(self, data: dict) -> list[dict[str, Any]]:
        semgrep_severity_map = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
        }

        findings: list[dict[str, Any]] = []
        for result in data.get("results", []):
            if not isinstance(result, dict):
                continue

            extra = result.get("extra")
            if not isinstance(extra, dict):
                extra = {}

            raw_severity = str(extra.get("severity", "WARNING")).upper()
            normalized_severity = semgrep_severity_map.get(raw_severity, "MEDIUM")

            check_id = result.get("check_id", "")
            if not check_id or not check_id.strip():
                logger.debug("Skipping Semgrep finding with empty check_id.")
                continue

            from devsecops_radar.core.reporting import redact_sensitive
            findings.append({
                "tool": self.name,
                "target": result.get("path", ""),
                "id": check_id,
                "severity": normalized_severity,
                "title": check_id,
                "description": redact_sensitive(extra.get("message", "")),
                "line": result.get("start", {}).get("line"),
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
            logger.error(f"Could not read Semgrep report: {e}")
            return []

        return self._parse_results(data)
