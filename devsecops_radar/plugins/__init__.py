# devsecops_radar/plugins/__init__.py
"""
Base plugin interface for security scanners.

For production use, inherit from ``BaseScanner`` in ``scanners.base``.
This lightweight class is intended for rapid prototyping or third‑party
integrations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from loguru import logger

from devsecops_radar.core.path_security import resolve_safe_path


class ScannerPlugin(ABC):
    """
    Minimal abstract base class for a security scanner plugin.

    If you use this class directly, you must implement all input validation
    yourself.  For built‑in scanners, prefer ``BaseScanner`` which already
    provides path confinement, safe command execution, and timeouts.
    """

    def __init__(self, allowed_base_dir: Path | None = None) -> None:
        """
        Args:
            allowed_base_dir: Root directory that the scanner is allowed to
                access.  If ``None``, defaults to the current working
                directory.  Paths outside this directory will be rejected by
                ``_validate_path``.
        """
        self.allowed_base_dir = (allowed_base_dir or Path.cwd()).resolve()

    # ------------------------------------------------------------------
    # Subclasses MUST provide these two properties
    # ------------------------------------------------------------------
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name of the scanner (used as entry‑point key)."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Version string of the scanner plugin."""
        ...

    # ------------------------------------------------------------------
    # Subclasses MUST implement parse (run is optional)
    # ------------------------------------------------------------------
    @abstractmethod
    def parse(self, file_path: str) -> list[dict[str, Any]]:
        """
        Parse a pre‑existing scan result file.

        Args:
            file_path: Path to the scanner's JSON/XML output file.

        Returns:
            A list of findings as dictionaries (matching ``FindingSchema``).

        Security:
            Always call ``_validate_path(file_path)`` before opening the file.
        """
        ...

    def run(self, target: str) -> list[dict[str, Any]] | None:
        """
        Execute a scan directly (optional).

        Args:
            target: A file path, directory, or container image to scan.

        Returns:
            A list of findings, or ``None`` if direct scanning is not
            supported.  The adapter will fall back to parsing in that case.

        Security:
            Always call ``_validate_path(target)`` if *target* is a file path.
        """
        return None  # not supported by default

    # ------------------------------------------------------------------
    # Path confinement helper – available to all plugins
    # ------------------------------------------------------------------
    def _validate_path(self, path: str) -> str | None:
        """
        Return the absolute, confined path if *path* is inside
        ``allowed_base_dir``, otherwise ``None``.

        Call this in your ``parse`` and ``run`` implementations before
        opening any file.
        """
        try:
            safe = resolve_safe_path(path, self.allowed_base_dir)
            return str(safe)
        except ValueError as e:
            logger.error(f"Security Violation in plugin '{self.name}': {e}")
            return None
