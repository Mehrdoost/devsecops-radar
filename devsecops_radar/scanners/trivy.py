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
        Validates a container image reference (e.g., 'nginx:latest',
        'repo/image:tag', 'ubuntu@sha256:...').
        Prevents Argument Injection and restricts to safe characters.
        """
        target = target.strip()

        # Prevent Argument Injection (e.g., passing "--help" or other flags)
        if target.startswith("-"):
            logger.error(
                "Security Violation: Target cannot start with a hyphen."
            )
            return ""

        # Allowed: alphanumeric, ., _, -, /, :, @
        # '@' is needed for image digests (e.g. ubuntu@sha256:abc...)
        if not re.match(r"^[a-zA-Z0-9_.:/@-]+$", target):
            logger.error(
                "Security Violation: Target contains invalid characters "
                "for a container image reference."
            )
            return ""

        # Ensure '@' only appears at most once (digest separator)
        if target.count("@") > 1:
            logger.error(
                "Security Violation: Target contains multiple '@' characters."
            )
            return ""

        # If '@' is present, it must separate image name from digest
        if "@" in target:
            parts = target.split("@")
            if len(parts) != 2 or not parts[0] or not parts[1]:
                logger.error(
                    "Security Violation: Invalid digest format in target."
                )
                return ""

        return target

    def run(self, target: str) -> list[ScannerFinding]:
        # 1. Image-specific validation (Do NOT use file path validation here)
        safe_target = self._validate_image_target(target)
        if not safe_target:
            return []

        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False
        ) as tmp:
            outfile = Path(tmp.name)

        try:
            # 2. Secure command execution without shell=True
            cmd = [
                self.binary_path,
                "image",
                "--format", "json",
                "--output", str(outfile),
                "--no-progress",
                safe_target,
            ]

            # 3. Timeouts and execution handled safely by BaseScanner
            result = self._safe_run_command(cmd)

            # 4. Check return code before attempting to parse
            if result.returncode != 0:
                logger.error(
                    f"Trivy exited with code {result.returncode}: "
                    f"{result.stderr[:300]}"
                )
                return []

            return self.parse(str(outfile))

        except Exception as e:
            logger.error(f"Trivy scan failed: {e}")
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
            logger.error(f"Trivy report not found: {file_path}")
            return []

        # 2. Memory Exhaustion Protection (50MB limit)
        try:
            if path.stat().st_size > 50 * 1024 * 1024:
                logger.error(
                    f"Trivy report {path.name} is too large. Skipping."
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

                # 4. Enrich description with package and version details
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
                    "line": None,  # Container scans have no line number
                })

        return findings
