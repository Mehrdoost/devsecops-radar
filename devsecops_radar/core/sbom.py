# devsecops_radar/core/sbom.py
"""
SBOM generation, dependency confusion detection, and VEX filtering.
All file operations are TOCTOU‑safe, sanitized, and output‑limited.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
from html import escape as html_escape
from pathlib import Path
from typing import Any

from loguru import logger

# Re‑use the same sanitizer as models.py for consistency
from devsecops_radar.core.models import _sanitize_html_and_control
from devsecops_radar.core.path_security import (
    resolve_safe_path,
    safe_read_open,
)
from devsecops_radar.core.utils import safe_subprocess_run


def _validate_file_size(file_path: Path, max_size_mb: int = 50) -> bool:
    try:
        if file_path.stat().st_size > max_size_mb * 1024 * 1024:
            logger.error(f"File {file_path.name} exceeds {max_size_mb}MB limit. Skipping.")
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
    Generate a CycloneDX SBOM using syft in a race‑free manner.
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

    # Unique temporary file for atomic output
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=str(safe_output.parent),
            prefix=".tmp_sbom_",
            suffix=".json",
        )
        os.close(tmp_fd)
        tmp_output = Path(tmp_path)
    except OSError as e:
        logger.error(f"Cannot create temporary file for SBOM: {e}")
        return None

    # Preserve original file permissions if they exist
    if safe_output.exists():
        try:
            shutil.copymode(str(safe_output), tmp_path)
        except OSError:
            pass

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
            max_output_mb=50,    # prevent huge output from filling RAM
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

    # Atomic replacement (permissions already copied)
    try:
        tmp_output.replace(safe_output)
    except OSError as e:
        logger.error(f"Failed to finalize SBOM file: {e}")
        tmp_output.unlink(missing_ok=True)
        return None

    # Read back the safely written file
    try:
        with safe_read_open(safe_output, base_dir=base) as f:
            sbom_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read SBOM file: {e}")
        return None

    # Sanitize paths: keep only the basename to avoid leaking absolute paths
    for component in sbom_data.get("components", []):
        if "name" in component:
            component["name"] = Path(component["name"]).name

    return sbom_data


def detect_dependency_confusion(
    manifest_path: str,
    internal_prefixes: list[str] | None = None,
    base_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Scan a package manifest for internal packages vulnerable to dependency confusion.
    """
    findings: list[dict[str, Any]] = []
    if internal_prefixes is None:
        internal_prefixes = []   # no default prefixes – must be explicitly configured

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
                            "package": html_escape(_sanitize_html_and_control(name)),
                            "version": html_escape(_sanitize_html_and_control(version)),
                            "risk": "Potential dependency confusion",
                        })

            elif manifest_path.endswith("requirements.txt"):
                if importlib.util.find_spec("requirements.parser"):
                    parser_mod = importlib.import_module("requirements.parser")
                    f.seek(0)
                    for req in parser_mod.parse(f):
                        pkg = req.name
                        if pkg and any(pkg.startswith(p) for p in internal_prefixes):
                            findings.append({
                                "package": html_escape(_sanitize_html_and_control(pkg)),
                                "version": html_escape(
                                    _sanitize_html_and_control(str(req.specifier) if req.specifier else "*")
                                ),
                                "risk": "Potential dependency confusion",
                            })
                else:
                    logger.info("`requirements-parser` not installed; using basic parsing.")
                    f.seek(0)
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        pkg = re.split(r'[=<>!~;\[\s]', line)[0].strip()
                        if pkg and any(pkg.startswith(p) for p in internal_prefixes):
                            findings.append({
                                "package": html_escape(_sanitize_html_and_control(pkg)),
                                "version": html_escape(_sanitize_html_and_control(line)),
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
    Filter out findings marked as not_affected or false_positive in a VEX document.
    Supports both 'id' and 'rule_id' fields in findings.
    """
    if not vex_file:
        return findings

    base = base_dir or Path.cwd()

    try:
        with safe_read_open(vex_file, base_dir=base) as vex_fh:
            vex = json.load(vex_fh)
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
            if isinstance(vid, str) and vid.strip():
                excluded_ids.add(vid.strip())

    if not excluded_ids:
        return findings

    filtered = []
    for f in findings:
        fid = f.get("id")
        rid = f.get("rule_id")
        if (isinstance(fid, str) and fid.strip() in excluded_ids) or \
           (isinstance(rid, str) and rid.strip() in excluded_ids):
            continue
        filtered.append(f)

    logger.info(f"VEX filter applied: {len(findings) - len(filtered)} findings excluded.")
    return filtered
