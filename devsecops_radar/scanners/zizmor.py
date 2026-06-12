import json
import tempfile
from pathlib import Path

from loguru import logger

from devsecops_radar.scanners.base import BaseScanner, ScannerFinding


class ZizmorScanner(BaseScanner):
    name = "zizmor"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "zizmor"

    def run(self, target: str) -> list[ScannerFinding]:
        # 1. Strict path validation to prevent Path Traversal
        safe_target = self._validate_target_path(target)
        if not safe_target:
            return []

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            outfile = Path(tmp.name)

        try:
            # 2. Secure command construction (no shell=True)
            cmd = [
                self.binary_path,
                "scan",
                safe_target,
                "--output", str(outfile),
                "--format", "json",
            ]

            # 3. Execution with built-in timeouts
            result = self._safe_run_command(cmd)

            # 4. Check return code
            if result.returncode != 0:
                logger.error(
                    f"Zizmor exited with code {result.returncode}: "
                    f"{result.stderr[:300]}"
                )
                return []

            return self.parse(str(outfile))

        except Exception as e:
            logger.error(f"Zizmor scan failed: {e}")
            return []
        finally:
            if outfile.exists():
                try:
                    outfile.unlink()
                except OSError as e:
                    logger.warning(
                        f"Could not delete temporary file {outfile}: {e}"
                    )

    def parse(self, file_path: str) -> list[ScannerFinding]:
        # 1. Path safety validation (prevent Path Traversal)
        safe_path = self._validate_target_path(file_path)
        if not safe_path:
            return []

        path = Path(safe_path)

        if not path.exists() or not path.is_file():
            logger.error(f"Zizmor report not found: {file_path}")
            return []

        # 2. Memory Exhaustion Protection (50MB limit)
        try:
            if path.stat().st_size > 50 * 1024 * 1024:
                logger.error(
                    f"Zizmor report {path.name} is too large. Skipping."
                )
                return []
        except OSError as e:
            logger.error(f"Cannot stat file {path}: {e}")
            return []

        # 3. Parse JSON safely
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Could not parse Zizmor output: {e}")
            return []

        findings: list[ScannerFinding] = []
        raw_findings = data.get("findings", [])

        for result in raw_findings:
            if not isinstance(result, dict):
                continue

            loc = result.get("location", {})
            findings.append({
                "tool": self.name,
                "target": result.get("path", ""),
                "id": result.get("rule_id", ""),
                "severity": str(result.get("severity", "UNKNOWN")).upper(),
                "title": result.get("message", ""),
                "description": result.get("description", ""),
                "line": loc.get("line") if isinstance(loc, dict) else None,
            })

        return findings
