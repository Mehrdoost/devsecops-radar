import json
import re
import tempfile
from pathlib import Path

from loguru import logger

from devsecops_radar.scanners.base import BaseScanner, ScannerFinding


class TrivyScanner(BaseScanner):
    name = "trivy"
    version = "1.0.0"

    def _default_binary_name(self) -> str:
        return "trivy"

    def _validate_image_target(self, target: str) -> str:
        """
        Validates a container image tag (e.g., 'nginx:latest', 'repo/image:tag').
        Prevents Argument Injection and restricts to safe characters.
        """
        target = target.strip()

        # Prevent Argument Injection (e.g., passing "--help" or other flags)
        if target.startswith("-"):
            logger.error("Security Violation: Target cannot start with a hyphen.")
            return ""

        # Allowed characters in container registries: alphanumeric, ., _, -, /, :
        if not re.match(r"^[a-zA-Z0-9_.:/-]+$", target):
            logger.error("Security Violation: Target contains invalid characters for a container image.")
            return ""

        return target

    def run(self, target: str) -> list[ScannerFinding]:
        # 1. Image-specific validation (Do NOT use file path validation here)
        safe_target = self._validate_image_target(target)
        if not safe_target:
            return []

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            outfile = Path(tmp.name)

        try:
            # 2. Secure command execution without shell=True
            # Added --no-progress to prevent CI/CD log pollution
            cmd = [
                self.binary_path,
                'image',
                '--format', 'json',
                '--output', str(outfile),
                '--no-progress',
                safe_target
            ]

            # 3. Timeouts and execution handled safely by BaseScanner
            self._safe_run_command(cmd)
            return self.parse(str(outfile))

        except Exception as e:
            logger.error(f"Trivy scan failed: {e}")
            return []
        finally:
            if outfile.exists():
                outfile.unlink()

    def parse(self, file_path: str) -> list[ScannerFinding]:
        path = Path(file_path)

        if not path.exists() or not path.is_file():
            return []

        # 4. Memory Exhaustion Protection (50MB limit)
        if path.stat().st_size > 50 * 1024 * 1024:
            logger.error(f"Trivy report {path.name} is too large. Skipping.")
            return []

        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Could not parse Trivy output: {e}")
            return []

        findings: list[ScannerFinding] = []
        for result in data.get("Results", []):
            if not isinstance(result, dict):
                continue

            target_name = result.get("Target", "Unknown")
            for vuln in result.get("Vulnerabilities", []):
                if not isinstance(vuln, dict):
                    continue

                # 5. Enrich description with package and version details securely
                pkg_name = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                base_desc = vuln.get("Description", "")

                enriched_desc = (
                    f"{base_desc}\n\n"
                    f"Package: {pkg_name} ({installed})\n"
                    f"Fixed Version: {fixed}"
                ).strip()

                findings.append({
                    "tool": self.name,
                    "target": target_name,
                    "id": vuln.get("VulnerabilityID", ""),
                    "severity": str(vuln.get("Severity", "UNKNOWN")).upper(),
                    "title": vuln.get("Title", ""),
                    "description": enriched_desc,
                    "line": 0
                })

        return findings
