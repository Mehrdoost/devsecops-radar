import os
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import ValidationError

from devsecops_radar.core.models import FindingSchema


class ScannerAdapter:
    """
    Adapter class to bridge raw scanner outputs with the internal FindingSchema.
    Ensures that data is validated and sanitized before reaching the core logic.
    """

    def __init__(self, scanner: Any) -> None:
        self.scanner = scanner

    def parse(self, file_path: str) -> list[FindingSchema]:
        """
        Safely reads and parses a result file.
        Implements defensive checks, path validation, and partial validation.
        """
        # 1. Path safety check (leverage the scanner's own validator if available)
        if hasattr(self.scanner, '_validate_target_path'):
            safe_path = self.scanner._validate_target_path(file_path)
            if not safe_path:
                logger.error(
                    f"Security block: file path '{file_path}' is outside the "
                    "allowed directory."
                )
                return []
            file_path = safe_path

        # 2. File existence and readability
        if not os.path.exists(file_path):
            logger.error(
                f"File validation failed: Path does not exist: {file_path}"
            )
            return []

        if not os.access(file_path, os.R_OK):
            logger.error(
                f"Permission Error: File is not readable: {file_path}"
            )
            return []

        # 3. File size check (prevent memory exhaustion)
        try:
            file_size = Path(file_path).stat().st_size
            if file_size > 50 * 1024 * 1024:  # 50 MB limit
                logger.error(
                    f"File {file_path} is too large ({file_size} bytes). Skipping."
                )
                return []
        except OSError as e:
            logger.error(f"Cannot stat file {file_path}: {e}")
            return []

        # 4. Delegate to the scanner and map to schema
        try:
            raw_data = self.scanner.parse(file_path)
            return self._safe_map_to_schema(raw_data)
        except Exception as e:
            logger.error(
                f"Scanner '{self.scanner.__class__.__name__}' failed to parse "
                f"file: {e}"
            )
            return []

    def run(self, target: str) -> list[FindingSchema]:
        """
        Executes a scan and converts results to the standardized schema.
        Partial failures in findings won't drop the entire scan result.
        """
        try:
            raw_data = self.scanner.run(target)
            return self._safe_map_to_schema(raw_data)
        except Exception as e:
            logger.error(
                f"Scanner '{self.scanner.__class__.__name__}' execution failed: {e}"
            )
            return []

    def _safe_map_to_schema(
        self, raw_findings: list[dict[str, Any]]
    ) -> list[FindingSchema]:
        """
        Processes a list of raw findings one by one.
        Invalid findings are logged and skipped instead of crashing the whole process.
        """
        if not isinstance(raw_findings, list):
            logger.warning(
                f"Scanner {self.scanner.__class__.__name__} returned non-list data."
            )
            return []

        valid_findings = []
        invalid_count = 0

        for f in raw_findings:
            try:
                valid_findings.append(FindingSchema(**f))
            except ValidationError as e:
                error_msg = (
                    e.errors()[0]['msg'] if e.errors() else "Unknown Schema Error"
                )
                logger.debug(
                    f"Skipping malformed finding from "
                    f"{self.scanner.__class__.__name__}: {error_msg}"
                )
                invalid_count += 1
            except Exception as e:
                logger.error(f"Unexpected error validating finding: {e}")
                invalid_count += 1

        if invalid_count > 0:
            logger.warning(
                f"Scanner {self.scanner.__class__.__name__}: "
                f"Successfully validated {len(valid_findings)} findings. "
                f"Discarded {invalid_count} malformed items."
            )

        return valid_findings
