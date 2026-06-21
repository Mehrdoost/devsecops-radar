# devsecops_radar/scanners/adapter.py
import os
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import ValidationError

from devsecops_radar.core.models import FindingSchema
from devsecops_radar.core.path_security import safe_read_open


class ScannerAdapter:
    """
    Adapter that bridges raw scanner outputs with the internal FindingSchema.
    All file accesses use TOCTOU‑safe operations.
    """

    def __init__(self, scanner: Any) -> None:
        self.scanner = scanner

    def parse(self, file_path: str) -> list[FindingSchema]:
        """
        Safely reads and validates a scanner result file.
        """
        try:
            f = safe_read_open(file_path, base_dir=Path.cwd())
        except ValueError as e:
            logger.error(f"Security block: {e}")
            return []
        except FileNotFoundError:
            logger.error(f"File not found or not accessible: {file_path}")
            return []
        except PermissionError:
            logger.error(f"Permission denied: {file_path}")
            return []
        except OSError as e:
            logger.error(f"Cannot open file {file_path}: {e}")
            return []

        with f:
            try:
                stat = os.fstat(f.fileno())
                if stat.st_size > 50 * 1024 * 1024:
                    logger.error(f"File {file_path} is too large ({stat.st_size} bytes). Skipping.")
                    return []
            except OSError as e:
                logger.error(f"Cannot stat file {file_path}: {e}")
                return []

            try:
                raw_data = self.scanner.parse(file_path)
                # If scanner supports built-in validation, use it; otherwise fall back
                if hasattr(self.scanner, '_validate_findings'):
                    raw_data = self.scanner._validate_findings(raw_data)
                return self._safe_map_to_schema(raw_data)
            except Exception as e:
                logger.error(f"Scanner '{self.scanner.__class__.__name__}' failed to parse file: {e}")
                return []

    def run(self, target: str) -> list[FindingSchema]:
        """
        Executes a scan and converts results to standardized schema.
        """
        try:
            raw_data = self.scanner.run(target)
            if hasattr(self.scanner, '_validate_findings'):
                raw_data = self.scanner._validate_findings(raw_data)
            return self._safe_map_to_schema(raw_data)
        except Exception as e:
            logger.error(f"Scanner '{self.scanner.__class__.__name__}' execution failed: {e}")
            return []

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
                error_msg = e.errors()[0]['msg'] if e.errors() else "Unknown Schema Error"
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
