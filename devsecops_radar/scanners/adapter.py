from typing import List
from devsecops_radar.plugins import ScannerPlugin
from devsecops_radar.core.models import FindingSchema

class ScannerAdapter:
    def __init__(self, scanner: ScannerPlugin):
        self.scanner = scanner

    def parse(self, file_path: str) -> List[FindingSchema]:
        raw = self.scanner.parse(file_path)
        return [FindingSchema(**f) for f in raw]

    def run(self, target: str) -> List[FindingSchema]:
        raw = self.scanner.run(target)
        return [FindingSchema(**f) for f in raw]