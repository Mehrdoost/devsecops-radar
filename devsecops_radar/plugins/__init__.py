from abc import ABC, abstractmethod
from typing import Any


class ScannerPlugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        ...

    @abstractmethod
    def parse(self, file_path: str) -> list[dict[str, Any]]:
        ...

    def run(self, target: str) -> list[dict[str, Any]]:
        raise NotImplementedError("Direct run not supported for this plugin.")
