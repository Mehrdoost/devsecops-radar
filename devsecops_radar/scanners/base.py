from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseScanner(ABC):
    @abstractmethod
    def run(self, target: str) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        pass