# devsecops_radar/scanners/zizmor.py
"""
Zizmor scanner – GitHub Actions security analysis.
"""

from __future__ import annotations

import json
from typing import Any

from loguru import logger

from devsecops_radar.scanners.base import BaseScanner


class ZizmorScanner(BaseScanner):
    name = "zizmor"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "zizmor"

    # ------------------------------------------------------------------
    # Core scan (called by BaseScanner.run after path validation)
    # ------------------------------------------------------------------
    def _run_internal(self, safe_target: str) -> list[dict[str, Any]]:
        cmd = [
            self.binary_path,
            "scan",
            safe_target,
            "--output", "-",       # <-- write to stdout
            "--format", "json",
        ]

        result = self._safe_run_command(cmd)

        # Zizmor may return 1 when findings are present
        if result.returncode not in (0, 1):
            logger.error(
                f"Zizmor exited with unexpected code {result.returncode}: "
                f"{result.stderr[:300]}"
            )
            return []

        # Parse stdout directly – no temp file needed
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Zizmor output: {e}")
            return []

        raw_findings = self._parse_results(data)
        return self._validate_findings(raw_findings)

    def _parse_results(self, data: list | dict) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        # Zizmor can output a list of diagnostics directly
        if isinstance(data, dict):
            diagnostics = data.get("diagnostics", [])
        elif isinstance(data, list):
            diagnostics = data
        else:
            logger.warning("Unexpected Zizmor output format.")
            return []

        for diag in diagnostics:
            if not isinstance(diag, dict):
                continue

            diag_id = diag.get("id", "")
            if not diag_id or not str(diag_id).strip():
                logger.debug("Skipping Zizmor finding with empty id.")
                continue

            title = diag.get("title", diag.get("message", ""))
            if not title or not str(title).strip():
                logger.debug("Skipping Zizmor finding with empty title.")
                continue

            # Make sure description is a string for redact_sensitive
            raw_desc = str(diag.get("description") or diag.get("message") or "")

            findings.append({
                "tool": self.name,
                "target": str(diag.get("file", diag.get("path", ""))),
                "id": str(diag_id),
                "severity": str(diag.get("severity", "UNKNOWN")).upper(),
                "title": str(title),
                "description": raw_desc,
                "line": diag.get("line"),
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
            logger.error(f"Could not read Zizmor report: {e}")
            return []

        return self._parse_results(data)
