from abc import ABC, abstractmethod
from typing import Any


class BaseScanner(ABC):
    @abstractmethod
    def run(self, target: str) -> list[dict[str, Any]]:
        pass

    @abstractmethod
    def parse(self, file_path: str) -> list[dict[str, Any]]:
        pass
