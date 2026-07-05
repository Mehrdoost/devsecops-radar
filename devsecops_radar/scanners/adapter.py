# devsecops_radar/scanners/adapter.py
"""
Adapter that bridges scanner instances with the internal FindingSchema.
All file accesses use TOCTOU‑safe operations and path confinement.
Supports scanners that implement only ``parse`` (via ``ScannerPlugin``)
by falling back to parsing when ``run`` returns ``None``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import ValidationError

from devsecops_radar.core.models import FindingSchema
from devsecops_radar.core.path_security import resolve_safe_path, safe_read_open


class ScannerAdapter:
    """Adapter that bridges raw scanner outputs with the internal FindingSchema."""

    def __init__(self, scanner: Any, base_dir: Path | None = None) -> None:
        self.scanner = scanner
        self.base_dir = (base_dir or Path.cwd()).resolve()

        # Force the scanner to use the same base directory for confinement
        if hasattr(self.scanner, "allowed_base_dir"):
            self.scanner.allowed_base_dir = self.base_dir

    # ------------------------------------------------------------------
    # Parse a pre‑existing report file
    # ------------------------------------------------------------------
    def parse(self, file_path: str) -> list[FindingSchema]:
        """Safely reads and validates a scanner result file."""
        try:
            f = safe_read_open(file_path, base_dir=self.base_dir)
        except ValueError as e:
            # safe_read_open now gives a generic message without path
            logger.error(f"Security block: {e}")
            return []
        except (FileNotFoundError, PermissionError, OSError) as e:
            logger.error(f"Cannot open file: {e}")
            return []

        with f:
            try:
                stat = os.fstat(f.fileno())
                if stat.st_size > 50 * 1024 * 1024:
                    logger.error(f"File too large ({stat.st_size} bytes). Skipping.")
                    return []
            except OSError as e:
                logger.error(f"Cannot stat file: {e}")
                return []

            try:
                raw_data = self.scanner.parse(file_path)
                if hasattr(self.scanner, "_validate_findings"):
                    raw_data = self.scanner._validate_findings(raw_data)
                return self._safe_map_to_schema(raw_data)
            except Exception as e:
                logger.error(f"Scanner '{self.scanner.__class__.__name__}' failed to parse file: {e}")
                return []

    # ------------------------------------------------------------------
    # Execute a scan (or fall back to parsing)
    # ------------------------------------------------------------------
    def run(self, target: str) -> list[FindingSchema]:
        """
        Execute a scan with path confinement and convert results.

        If the underlying scanner does not support direct execution
        (i.e. ``run`` returns ``None``) and *target* looks like a file,
        this method automatically delegates to :meth:`parse`.
        """
        if not target:
            logger.error("Empty target is not allowed.")
            return []

        # Decide whether to apply path confinement
        if _looks_like_path(target):
            try:
                # This will reject paths that escape base_dir
                resolve_safe_path(target, self.base_dir)
            except ValueError as e:
                logger.error(f"Target path rejected: {e}")
                return []
        # else: non‑path target (e.g. Docker image) – let scanner handle it

        try:
            raw_data = self.scanner.run(target)
        except Exception as e:
            logger.error(f"Scanner '{self.scanner.__class__.__name__}' execution failed: {e}")
            return []

        if raw_data is None:
            if Path(target).is_file():
                logger.info(
                    f"Scanner '{self.scanner.__class__.__name__}' does not support "
                    f"direct execution; falling back to parsing file '{target}'."
                )
                return self.parse(target)
            else:
                logger.error(
                    f"Scanner '{self.scanner.__class__.__name__}' cannot run on target "
                    f"'{target}' (no direct execution and target is not a file)."
                )
                return []

        if hasattr(self.scanner, "_validate_findings"):
            raw_data = self.scanner._validate_findings(raw_data)
        return self._safe_map_to_schema(raw_data)

    # ------------------------------------------------------------------
    # Map raw dicts to Pydantic models
    # ------------------------------------------------------------------
    def _safe_map_to_schema(self, raw_findings: list[dict[str, Any]]) -> list[FindingSchema]:
        if not isinstance(raw_findings, list):
            logger.warning(f"Scanner {self.scanner.__class__.__name__} returned non‑list data.")
            return []

        valid_findings = []
        invalid_count = 0
        for f in raw_findings:
            try:
                valid_findings.append(FindingSchema(**f))
            except ValidationError as e:
                error_msg = e.errors()[0]["msg"] if e.errors() else "Unknown Schema Error"
                logger.debug(f"Skipping malformed finding from {self.scanner.__class__.__name__}: {error_msg}")
                invalid_count += 1
            except Exception as e:
                logger.error(f"Unexpected error validating finding: {e}")
                invalid_count += 1

        if invalid_count > 0:
            logger.warning(
                f"Scanner {self.scanner.__class__.__name__}: "
                f"{len(valid_findings)} valid, {invalid_count} malformed items discarded."
            )
        return valid_findings


# --------------------------------------------------------------------------
# Helper: decide whether a target should be treated as a file path
# --------------------------------------------------------------------------
def _looks_like_path(target: str) -> bool:
    """Return True if *target* appears to be a file path."""
    if "/" in target or "\\" in target:
        return True
    # Docker image names usually contain ':' and no slashes
    if ":" in target and "/" not in target:
        return False
    return True
