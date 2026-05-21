
from devsecops_radar.core.models import FindingSchema
from devsecops_radar.plugins import ScannerPlugin


class ScannerAdapter:
    def __init__(self, scanner: ScannerPlugin):
        self.scanner = scanner

    def parse(self, file_path: str) -> list[FindingSchema]:
        raw = self.scanner.parse(file_path)
        return [FindingSchema(**f) for f in raw]

    def run(self, target: str) -> list[FindingSchema]:
        raw = self.scanner.run(target)
        return [FindingSchema(**f) for f in raw]
