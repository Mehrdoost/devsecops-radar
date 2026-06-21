# devsecops_radar/core/remediation.py
import os
import re
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

from devsecops_radar.core.path_security import (
    atomic_write,
    resolve_safe_path,
    safe_read_open,
)
from devsecops_radar.core.utils import safe_subprocess_run

BACKUP_DIR = Path.home() / ".devsecops-radar" / "backups"
PATCH_DIR = Path.home() / ".devsecops-radar" / "patches"


def _init_dirs() -> None:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    PATCH_DIR.mkdir(parents=True, exist_ok=True)


def _backup_file(target_file: str, base_dir: Path | None = None) -> Path | None:
    """Create a safe backup of *target_file* inside BACKUP_DIR."""
    _init_dirs()
    base = base_dir or Path.cwd()
    try:
        safe_target = resolve_safe_path(target_file, base)
    except ValueError as e:
        logger.error(f"Cannot backup unsafe path: {e}")
        return None

    if not safe_target.is_file():
        logger.warning(f"Backup skipped: file not found {safe_target}")
        return None

    rel_path = safe_target.relative_to(base)
    safe_name = f"{uuid.uuid4().hex}_{str(rel_path).replace(os.sep, '_')}.bak"
    backup_path = BACKUP_DIR / safe_name

    try:
        with safe_read_open(safe_target, base_dir=base) as src:
            content = src.read()
        with atomic_write(backup_path, base_dir=BACKUP_DIR) as dst:
            dst.write(content)
        logger.debug(f"Backed up {safe_target} to {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Backup failed for {target_file}: {e}")
        return None


def apply_patch(
    finding: dict[str, Any],
    patch_content: str,
    base_dir: Path | None = None,
    require_evidence: bool = False,      # <-- new parameter
) -> bool:
    """
    Apply *patch_content* to the file described in *finding*.

    If *require_evidence* is True, the patch will only be applied when the
    current content of the target lines matches the finding's evidence.
    """
    base = base_dir or Path.cwd()
    target_file: str | None = finding.get("target")
    raw_line = finding.get("line")
    evidence = finding.get("evidence")

    if not target_file or raw_line is None:
        logger.warning("Finding is missing 'target' or 'line'. Cannot apply patch.")
        return False

    try:
        line_num = int(raw_line)
    except (ValueError, TypeError):
        logger.error(f"Invalid line number format: {raw_line}")
        return False

    # Validate target path confinement
    try:
        safe_target = resolve_safe_path(target_file, base)
    except ValueError as e:
        logger.error(f"Security Error: {e}")
        return False

    if not safe_target.is_file():
        logger.error(f"Target file does not exist: {target_file}")
        return False

    # Read current file content safely
    try:
        with safe_read_open(safe_target, base_dir=base) as f:
            original_lines = f.readlines()
    except Exception as e:
        logger.error(f"Cannot read target file {safe_target}: {e}")
        return False

    patch_lines = patch_content.splitlines(keepends=True)
    if not patch_lines:
        logger.warning("Patch content is empty. Nothing to apply.")
        return False

    line_index = line_num - 1
    if not (0 <= line_index < len(original_lines)):
        logger.error(f"Line number {line_num} is out of bounds for {safe_target}")
        return False

    # ----------- Evidence check ----------
    if evidence is not None:
        end_idx = min(line_index + len(patch_lines), len(original_lines))
        current_snippet = "".join(original_lines[line_index:end_idx]).strip()
        expected_snippet = str(evidence).strip()
        if current_snippet != expected_snippet:
            logger.error(
                f"Evidence mismatch for {safe_target} at line {line_num}. "
                f"Expected:\n{expected_snippet!r}\nGot:\n{current_snippet!r}"
            )
            return False
        logger.info(f"Evidence matched for {safe_target}:{line_num}")
    else:
        if require_evidence:
            logger.warning(
                f"No evidence provided for {safe_target}:{line_num}. "
                "Patch skipped because evidence is required."
            )
            return False
        logger.warning(
            f"No evidence provided for {safe_target}:{line_num}. "
            "Patch applied without content verification – this is risky."
        )
    # ------------------------------------

    # Create backup before modifying
    backup_path = _backup_file(target_file, base_dir=base)
    if not backup_path:
        logger.error("Cannot proceed without a successful backup.")
        return False

    # Apply the change
    end_index = min(line_index + len(patch_lines), len(original_lines))
    patched_lines = (
        original_lines[:line_index] + patch_lines + original_lines[end_index:]
    )

    # Write atomically
    try:
        with atomic_write(safe_target, base_dir=base) as f:
            f.writelines(patched_lines)
    except Exception as e:
        logger.error(f"Atomic write failed for {safe_target}: {e}")
        # Restore from backup
        try:
            shutil.copy2(str(backup_path), str(safe_target))
            logger.info(f"Rolled back {safe_target} from backup.")
        except Exception as restore_err:
            logger.critical(
                f"CRITICAL: Rollback also failed! Manual intervention required for {safe_target}: {restore_err}"
            )
        return False

    logger.success(f"Successfully patched {safe_target} at line {line_num}")
    return True


def generate_remediation_guide(
    ai_remediations: list[dict[str, Any]],
) -> str:
    if not ai_remediations:
        return "No automated remediations provided by the AI."

    guide = [
        "\n🛡️  PIPELINE SENTINEL - REMEDIATION GUIDE  🛡️",
        "=" * 45,
    ]
    for rem in ai_remediations:
        guide.append(
            f"\n[ID: {rem.get('finding_id', 'UNKNOWN')}] "
            f"{rem.get('title', 'Fix Request')}"
        )
        steps = rem.get("remediation_steps", [])
        if not steps:
            guide.append("  - Manual investigation required.")
        for idx, step in enumerate(steps, 1):
            guide.append(f"  {idx}. {step}")

    return "\n".join(guide)


def auto_fix(
    findings: list[dict[str, Any]],
    ai_summary: dict[str, Any],
    require_evidence: bool = True,   # safe default for automated mode
) -> set[str]:
    modified_files: set[str] = set()
    ai_rems = {
        r.get("finding_id"): r
        for r in ai_summary.get("top_remediations", [])
    }

    # Sort findings so patches are applied from last line to first,
    # preventing line‑number shifts for patches on the same file.
    sorted_findings = sorted(
        findings,
        key=lambda f: f.get("line", 0),
        reverse=True,
    )

    for f in sorted_findings:
        fid = f.get("id")
        if fid in ai_rems:
            patch = ai_rems[fid].get("patch_content")
            if patch and apply_patch(f, patch, require_evidence=require_evidence):
                target = f.get("target")
                if target and isinstance(target, str):
                    modified_files.add(target)

    return modified_files


def generate_pr(
    modified_files: set[str],
    branch: str = "sentinel-auto-fix",
) -> None:
    if not modified_files:
        logger.info("No files were modified. Skipping PR generation.")
        return

    if not re.match(r"^[a-zA-Z0-9_\-]+$", branch):
        logger.error(f"Invalid branch name '{branch}'. Aborting PR generation.")
        return

    _init_dirs()

    # Ensure we are in a git repository
    try:
        safe_subprocess_run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Not a git repository or git not found: {e.stderr}")
        return
    except FileNotFoundError:
        logger.error("Git executable not found. Ensure git is installed.")
        return

    # Stage the modified files – this is necessary because auto_fix already
    # changed them, so the working tree is dirty.
    for file in modified_files:
        try:
            safe_subprocess_run(
                ["git", "add", file],
                check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stage {file}: {e.stderr}")

    unique_branch = f"{branch}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"

    try:
        safe_subprocess_run(
            ["git", "checkout", "-b", unique_branch],
            check=True, capture_output=True, text=True,
        )
        safe_subprocess_run(
            ["git", "commit", "-m",
             f"Security fixes applied by Pipeline Sentinel [{unique_branch}]"],
            check=True, capture_output=True, text=True,
        )

        # Attempt to push; store patch locally if offline
        try:
            safe_subprocess_run(
                ["git", "push", "-u", "origin", unique_branch],
                check=True, capture_output=True, text=True,
            )
            logger.success(f"✅ Pushed automated fixes to branch: {unique_branch}")
        except subprocess.CalledProcessError:
            logger.warning("Push failed — storing patch file locally for manual upload.")
            patch_file = PATCH_DIR / f"{unique_branch}.patch"
            safe_subprocess_run(
                ["git", "format-patch", "-1", "HEAD", "-o", str(PATCH_DIR)],
                check=True, capture_output=True, text=True,
            )
            logger.info(f"Patch file saved to {patch_file}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Git operation failed during PR generation: {e.stderr}")
    except FileNotFoundError:
        logger.error("Git executable not found.")
