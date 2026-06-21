from abc import ABC, abstractmethod
from typing import Any


class ScannerPlugin(ABC):
    """
    Minimal abstract base class for a security scanner plugin.

    For full security features (path validation, safe command execution,
    timeouts, etc.), inherit from ``BaseScanner`` in
    ``devsecops_radar.scanners.base`` instead of this class.

    If you use this class directly, you are responsible for implementing
    all input validation and secure subprocess calls yourself.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Unique name of the scanner.

        Used as the entry‑point key and shown in the dashboard.
        """
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """
        Version of the scanner plugin.
        """
        ...

    @abstractmethod
    def parse(self, file_path: str) -> list[dict[str, Any]]:
        """
        Parse a pre‑existing scan result file.

        Args:
            file_path: Path to the scanner's JSON/XML output file.

        Returns:
            A list of findings, each as a dictionary with keys matching
            the ``FindingSchema`` model (tool, id, severity, target,
            title, description, line).

        Security warning:
            Validate ``file_path`` to prevent path‑traversal attacks.
        """
        ...

    def run(self, target: str) -> list[dict[str, Any]]:
        """
        Execute a scan directly (optional).

        Args:
            target: A file path, directory, or container image to scan.

        Raises:
            NotImplementedError: By default, indicating that the plugin
                only supports parsing of existing reports.

        Security warning:
            Validate ``target`` and use safe command execution.
        """
        raise NotImplementedError(
            "Direct run not supported for this plugin. "
            "Use `parse` with a pre‑generated report."
        )
