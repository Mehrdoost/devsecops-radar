# devsecops_radar/core/sbom.py
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from loguru import logger

from devsecops_radar.core.path_security import (
    resolve_safe_path,
    safe_read_open,
)
from devsecops_radar.core.utils import safe_subprocess_run


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
    target_dir: str,
    output_file: str = "sbom.json",
    base_dir: Path | None = None,
) -> dict[str, Any] | None:
    """
    Generate a CycloneDX SBOM using syft.
    *base_dir* confines both target and output to a trusted root (default cwd).
    """
    base = base_dir or Path.cwd()

    # Validate target directory confinement
    try:
        safe_target = resolve_safe_path(target_dir, base)
    except ValueError as e:
        logger.error(f"SBOM generation blocked: {e}")
        return None

    if not safe_target.is_dir():
        logger.error(f"Target directory does not exist: {target_dir}")
        return None

    # Validate output file path confinement
    try:
        safe_output = resolve_safe_path(output_file, base)
    except ValueError as e:
        logger.error(f"SBOM output file blocked: {e}")
        return None

    if not shutil.which("syft"):
        logger.error("syft is not installed. Cannot generate SBOM.")
        return None

    # syft writes to the output file directly – to make it atomic we
    # first generate into a temporary file and then atomically replace.
    tmp_output = safe_output.with_name(f".tmp-{safe_output.name}")
    try:
        safe_subprocess_run(
            [
                "syft", "scan", str(safe_target),
                "-o", "cyclonedx-json",
                "--output", str(tmp_output),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"syft failed: {e.stderr}")
        tmp_output.unlink(missing_ok=True)
        return None
    except subprocess.TimeoutExpired:
        logger.error("syft timed out.")
        tmp_output.unlink(missing_ok=True)
        return None
    except Exception as e:
        logger.error(f"SBOM generation failed: {e}")
        tmp_output.unlink(missing_ok=True)
        return None

    if not tmp_output.exists():
        logger.error("Temporary SBOM file was not created.")
        return None

    if not _validate_file_size(tmp_output):
        tmp_output.unlink(missing_ok=True)
        return None

    # Atomically move to final destination
    try:
        tmp_output.replace(safe_output)
    except OSError as e:
        logger.error(f"Failed to finalize SBOM file: {e}")
        tmp_output.unlink(missing_ok=True)
        return None

    # Read the now safely written file
    try:
        with safe_read_open(safe_output, base_dir=base) as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to read SBOM file: {e}")
        return None


def detect_dependency_confusion(
    manifest_path: str,
    internal_prefixes: list[str] | None = None,
    base_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Scan a package manifest (package.json or requirements.txt) for internal
    packages that could be vulnerable to dependency confusion.
    """
    findings: list[dict[str, Any]] = []
    if internal_prefixes is None:
        internal_prefixes = ["mycompany-", "internal-"]

    base = base_dir or Path.cwd()

    try:
        f = safe_read_open(manifest_path, base_dir=base)
    except ValueError as e:
        logger.error(f"Blocked reading manifest: {e}")
        return findings
    except (FileNotFoundError, PermissionError, OSError) as e:
        logger.error(f"Cannot read manifest {manifest_path}: {e}")
        return findings

    with f:
        try:
            if manifest_path.endswith("package.json"):
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
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Simple extraction: remove version specifiers, extras, and env markers
                    # This is intentionally basic – a production system would use a proper parser.
                    pkg = (
                        line.split("==")[0]
                        .split(">=")[0]
                        .split("<=")[0]
                        .split("~=")[0]
                        .split("!=")[0]
                        .split("@")[0]           # direct URL installations
                        .split("[")[0]           # extras
                        .split(";")[0]           # environment markers
                        .strip()
                    )
                    if pkg and any(pkg.startswith(p) for p in internal_prefixes):
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
    findings: list[dict[str, Any]],
    vex_file: str,
    base_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Filter out findings that are marked as not_affected or false_positive in a
    CycloneDX VEX document.
    """
    if not vex_file:
        return findings

    base = base_dir or Path.cwd()

    try:
        with safe_read_open(vex_file, base_dir=base) as f:
            vex = json.load(f)
    except ValueError as e:
        logger.error(f"VEX file path is not allowed: {e}")
        return findings
    except (FileNotFoundError, PermissionError, OSError, json.JSONDecodeError) as e:
        logger.error(f"Failed to read VEX file: {e}")
        return findings

    excluded_ids = set()
    for vuln in vex.get("vulnerabilities", []):
        analysis = vuln.get("analysis", {})
        if analysis.get("state") in ["not_affected", "false_positive"]:
            vid = vuln.get("id")
            # Prevent None from being added – only add if it's a non‑empty string
            if isinstance(vid, str) and vid.strip():
                excluded_ids.add(vid.strip())

    if not excluded_ids:
        return findings

    filtered = [f for f in findings if f.get("id") not in excluded_ids]
    logger.info(
        f"VEX filter applied: {len(findings) - len(filtered)} findings excluded."
    )
    return filtered
