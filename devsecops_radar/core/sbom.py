import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from loguru import logger


def _is_safe_path(target: str, base_dir: Path | None = None) -> bool:
    """Prevent Path Traversal attacks."""
    if base_dir is None:
        base_dir = Path.cwd()
    try:
        abs_target = Path(target).resolve(strict=False)
        return abs_target.is_relative_to(base_dir.resolve())
    except Exception as e:
        logger.error(f"Path resolution error for {target}: {e}")
        return False


def _validate_file_size(file_path: Path, max_size_mb: int = 50) -> bool:
    """Check that the file does not exceed the maximum allowed size."""
    try:
        if file_path.stat().st_size > max_size_mb * 1024 * 1024:
            logger.error(
                f"File {file_path.name} exceeds {max_size_mb}MB limit. Skipping."
            )
            return False
    except OSError as e:
        logger.error(f"Cannot stat file {file_path}: {e}")
        return False
    return True


def generate_sbom(
    target_dir: str, output_file: str = "sbom.json"
) -> dict[str, Any] | None:
    """
    Generate a CycloneDX SBOM using syft.
    Both target_dir and output_file are validated to stay inside the current
    working directory.
    """
    # Validate paths
    if not _is_safe_path(target_dir) or not _is_safe_path(output_file):
        logger.error(
            "SBOM generation blocked: target directory or output file is "
            "outside allowed path."
        )
        return None

    target_path = Path(target_dir).resolve()
    if not target_path.is_dir():
        logger.error(f"Target directory does not exist: {target_dir}")
        return None

    # Ensure syft is available
    if not shutil.which("syft"):
        logger.error("syft is not installed. Cannot generate SBOM.")
        return None

    output_path = Path(output_file).resolve()
    try:
        subprocess.run(
            [
                "syft", "scan", str(target_path),
                "-o", "cyclonedx-json",
                "--output", str(output_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if not output_path.exists():
            logger.error(f"SBOM file was not created: {output_file}")
            return None

        # Protect against oversized files
        if not _validate_file_size(output_path):
            return None

        with open(output_path, encoding="utf-8") as f:
            return json.load(f)
    except subprocess.CalledProcessError as e:
        logger.error(f"syft failed: {e.stderr}")
    except subprocess.TimeoutExpired:
        logger.error("syft timed out.")
    except Exception as e:
        logger.error(f"SBOM generation failed: {e}")
    return None


def detect_dependency_confusion(
    manifest_path: str, internal_prefixes: list[str] | None = None
) -> list[dict[str, Any]]:
    """
    Scan a package manifest for internal packages that could be vulnerable to
    dependency confusion. Supports package.json and requirements.txt.
    """
    findings: list[dict[str, Any]] = []
    if internal_prefixes is None:
        internal_prefixes = ["mycompany-", "internal-"]

    if not _is_safe_path(manifest_path):
        logger.error(
            f"Blocked reading manifest: {manifest_path} is outside allowed path."
        )
        return findings

    manifest_file = Path(manifest_path)
    if not manifest_file.is_file():
        logger.warning(f"Manifest file not found: {manifest_path}")
        return findings

    try:
        if manifest_path.endswith("package.json"):
            with open(manifest_file, encoding="utf-8") as f:
                data = json.load(f)
            dependencies = data.get("dependencies", {})
            dev_dependencies = data.get("devDependencies", {})
            all_deps = {**dependencies, **dev_dependencies}
            for name, version in all_deps.items():
                if any(name.startswith(p) for p in internal_prefixes):
                    findings.append({
                        "package": name,
                        "version": version,
                        "risk": "Potential dependency confusion",
                    })
        elif manifest_path.endswith("requirements.txt"):
            with open(manifest_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Extract package name (before ==, >=, etc.)
                    pkg = (
                        line.split("==")[0]
                        .split(">=")[0]
                        .split("<=")[0]
                        .split("~=")[0]
                        .split("!=")[0]
                        .strip()
                    )
                    if any(pkg.startswith(p) for p in internal_prefixes):
                        findings.append({
                            "package": pkg,
                            "version": line,
                            "risk": "Potential dependency confusion",
                        })
        else:
            logger.info(f"Unsupported manifest format: {manifest_path}")
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in {manifest_path}")
    except Exception as e:
        logger.error(f"Error scanning manifest {manifest_path}: {e}")

    return findings


def apply_vex_filter(
    findings: list[dict[str, Any]], vex_file: str
) -> list[dict[str, Any]]:
    """
    Filter out findings that are marked as not_affected or false_positive in a
    CycloneDX VEX document.
    """
    if not vex_file or not os.path.exists(vex_file):
        return findings

    if not _is_safe_path(vex_file):
        logger.error(f"VEX file path is not allowed: {vex_file}")
        return findings

    try:
        with open(vex_file, encoding="utf-8") as f:
            vex = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read VEX file: {e}")
        return findings

    excluded_ids = set()
    for vuln in vex.get("vulnerabilities", []):
        analysis = vuln.get("analysis", {})
        if analysis.get("state") in ["not_affected", "false_positive"]:
            excluded_ids.add(vuln.get("id"))

    if not excluded_ids:
        return findings

    filtered = [f for f in findings if f.get("id") not in excluded_ids]
    logger.info(
        f"VEX filter applied: {len(findings) - len(filtered)} findings excluded."
    )
    return filtered
