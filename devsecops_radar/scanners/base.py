# devsecops_radar/scanners/base.py
"""
Abstract base class for all security scanners.

Provides:
- Mandatory path validation via template method pattern
- Streaming output capture with size limit
- Finding validation against FindingSchema
"""

from __future__ import annotations

import subprocess
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import ValidationError

from devsecops_radar.core.models import FindingSchema
from devsecops_radar.core.path_security import resolve_safe_path


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

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
        if not _binary_exists(self.binary_path):
            logger.warning(
                f"Scanner binary '{self.binary_path}' not found in PATH. "
                "Ensure it is installed before running scans."
            )

    # ------------------------------------------------------------------
    # Subclasses must implement these two
    # ------------------------------------------------------------------
    @abstractmethod
    def _default_binary_name(self) -> str:
        """Return the scanner's binary name (e.g., 'trivy')."""
        ...

    @abstractmethod
    def _run_internal(self, safe_target: str) -> list[dict[str, Any]]:
        """
        Execute the scan on an already‑validated target and return raw findings.
        """
        ...

    @abstractmethod
    def parse(self, file_path: str) -> list[dict[str, Any]]:
        """
        Parse an existing scanner result file and return raw findings.
        """
        ...

    # ------------------------------------------------------------------
    # Template method – enforces path validation for all scans
    # ------------------------------------------------------------------
    def run(self, target: str) -> list[dict[str, Any]]:
        """
        Validate the target path and execute the scan.

        If *target* is a file/directory path, it must reside inside
        ``allowed_base_dir``.  Other targets (e.g. Docker images) are
        forwarded unchanged to ``_run_internal``.
        """
        if not target:
            logger.error("Empty target is not allowed.")
            return []

        # Resolve and validate if the target looks like a path.
        # For image names (e.g. "nginx:latest"), skip validation.
        if _looks_like_path(target):
            safe_target = self._validate_target_path(target)
            if safe_target is None:
                return []
        else:
            safe_target = target

        return self._run_internal(safe_target)

    # ------------------------------------------------------------------
    # Security helpers
    # ------------------------------------------------------------------
    def _validate_target_path(self, target: str) -> str | None:
        """
        Return the absolute, symlink‑free path if *target* is inside the
        allowed base directory, otherwise ``None``.

        Because ``resolve_safe_path`` follows symlinks, the returned path
        is immune to subsequent symlink‑swap attacks.
        """
        try:
            safe = resolve_safe_path(target, self.allowed_base_dir)
            return str(safe)
        except ValueError as e:
            logger.error(f"Security Violation: {e}")
            return None

    def _safe_run_command(
        self, cmd_args: list[str], max_output_mb: int = 50
    ) -> subprocess.CompletedProcess:
        """
        Execute a whitelisted command and guard against excessive output.

        Output is read in chunks; if the total size exceeds the limit,
        the process is killed and an empty result with an error message
        is returned.
        """
        if not cmd_args:
            raise ValueError("Command arguments cannot be empty.")

        # Use Popen for streaming capture
        max_bytes = max_output_mb * 1024 * 1024
        try:
            proc = subprocess.Popen(    # noqa: S603
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to start process: {e}")
            raise

        # Read stdout and stderr concurrently with a size limit
        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []
        total = 0
        killed = False

        def _read_stream(stream, chunks):
            nonlocal total, killed
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    killed = True
                    proc.kill()
                    break
                chunks.append(chunk)

        t1 = threading.Thread(target=_read_stream, args=(proc.stdout, stdout_chunks))
        t2 = threading.Thread(target=_read_stream, args=(proc.stderr, stderr_chunks))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        returncode = proc.wait()

        stdout = "".join(stdout_chunks) if not killed else ""
        stderr = "".join(stderr_chunks) if not killed else ""
        if killed:
            logger.error(
                f"Output of {cmd_args[0]} exceeded {max_output_mb}MB limit. "
                "Process killed and output discarded."
            )
            returncode = 1
            stderr = f"Output exceeded {max_output_mb}MB limit."

        return subprocess.CompletedProcess(
            args=cmd_args,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def _validate_findings(self, raw_findings: list[dict]) -> list[dict[str, Any]]:
        """
        Validate each raw finding against FindingSchema and return
        cleaned dicts that include all default values.
        """
        validated: list[dict[str, Any]] = []
        for item in raw_findings:
            try:
                valid = FindingSchema(**item)
                validated.append(valid.model_dump())
            except ValidationError as e:
                logger.debug(f"Discarded invalid scanner finding: {e.errors()[0]['msg']}")
        return validated


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _binary_exists(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


def _looks_like_path(target: str) -> bool:
    """
    Return True if *target* appears to be a file path.
    Simple heuristic: contains a slash/backslash, or is a simple filename
    that might exist.
    """
    if "/" in target or "\\" in target:
        return True
    # Docker image names usually contain ':' and no slashes
    if ":" in target and "/" not in target:
        return False
    return True
