# devsecops_radar/scanners/base.py
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TypedDict

from loguru import logger
from pydantic import ValidationError

from devsecops_radar.core.models import FindingSchema
from devsecops_radar.core.path_security import resolve_safe_path
from devsecops_radar.core.utils import safe_subprocess_run


class ScannerFinding(TypedDict, total=False):
    id: str
    tool: str
    target: str
    severity: str
    title: str
    description: str
    line: int | None


class BaseScanner(ABC):
    """
    Abstract Base Class for all security scanners.
    Enforces security contracts (Path Traversal protection, Command execution safety)
    and output standardization.
    """

    def __init__(
        self,
        timeout: int = 300,
        binary_path: str | None = None,
        allowed_base_dir: Path | None = None,
    ) -> None:
        self.timeout = timeout
        self.binary_path = binary_path or self._default_binary_name()
        self.allowed_base_dir = (
            allowed_base_dir.resolve() if allowed_base_dir else Path.cwd()
        )
        if not shutil.which(self.binary_path):
            logger.warning(
                f"Scanner binary '{self.binary_path}' not found in PATH. "
                "Ensure it is installed before running scans."
            )

    @abstractmethod
    def _default_binary_name(self) -> str:
        pass

    def _validate_target_path(self, target: str) -> str | None:
        """Validate that *target* is inside the allowed base directory (TOCTOU‑safe)."""
        try:
            safe = resolve_safe_path(target, self.allowed_base_dir)
            return str(safe)
        except ValueError as e:
            logger.error(f"Security Violation: {e}")
            return None

    def _safe_run_command(
        self, cmd_args: list[str], max_output_mb: int = 50
    ) -> subprocess.CompletedProcess:
        if not cmd_args:
            raise ValueError("Command arguments cannot be empty.")

        executable = shutil.which(cmd_args[0])
        if executable is None:
            raise FileNotFoundError(
                f"Required executable not found: {cmd_args[0]}"
            )

        resolved_cmd = [executable] + cmd_args[1:]

        logger.debug(f"Executing {executable} securely.")

        try:
            result = safe_subprocess_run(
                resolved_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.error(
                f"Scanner '{cmd_args[0]}' timed out after {self.timeout} seconds."
            )
            raise
        except FileNotFoundError:
            logger.error(f"Executable not found in PATH: {cmd_args[0]}")
            raise

        # Check output size – reject entirely if too large (do NOT truncate JSON)
        max_bytes = max_output_mb * 1024 * 1024
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        total_size = len(stdout.encode()) + len(stderr.encode())

        if total_size > max_bytes:
            logger.error(
                f"Output of {cmd_args[0]} exceeds {max_output_mb}MB limit. "
                "Output discarded to prevent memory exhaustion."
            )
            result.stdout = ""
            result.stderr = f"Output exceeded {max_output_mb}MB limit."
            result.returncode = 1

        return result

    def _validate_findings(self, raw_findings: list[dict]) -> list[dict]:
        """Validate raw scanner output against FindingSchema, discarding invalid entries."""
        validated: list[dict] = []
        for item in raw_findings:
            try:
                FindingSchema(**item)
                validated.append(item)
            except ValidationError as e:
                logger.debug(f"Discarded invalid scanner finding: {e.errors()[0]['msg']}")
        return validated

    @abstractmethod
    def run(self, target: str) -> list[ScannerFinding]:
        pass

    @abstractmethod
    def parse(self, file_path: str) -> list[ScannerFinding]:
        pass
