import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TypedDict

from loguru import logger

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
        try:
            target_path = Path(target).resolve(strict=False)
            if not target_path.is_relative_to(self.allowed_base_dir):
                logger.error(
                    f"Security Violation: Target path '{target}' is outside "
                    "the allowed directory."
                )
                return None
            return str(target_path)
        except Exception as e:
            logger.error(f"Path validation failed for '{target}': {e}")
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

        cmd_args[0] = executable

        logger.debug(f"Executing {cmd_args[0]} securely.")

        try:
            result = safe_subprocess_run(
                cmd_args,
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

        # Truncate output if it exceeds memory limit
        max_bytes = max_output_mb * 1024 * 1024
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        if len(stdout.encode()) + len(stderr.encode()) > max_bytes:
            logger.warning(
                f"Output of {cmd_args[0]} exceeds {max_output_mb}MB limit. "
                "Truncating to prevent memory exhaustion."
            )
            # Keep first half MB of each, roughly
            half = max_bytes // 2
            result.stdout = stdout[:half]
            result.stderr = stderr[:half]
        return result

    @abstractmethod
    def run(self, target: str) -> list[ScannerFinding]:
        pass

    @abstractmethod
    def parse(self, file_path: str) -> list[ScannerFinding]:
        pass
