# devsecops_radar/core/remediation.py
"""
Automated patching engine with evidence checks, backup, sandboxed dry‑run,
and Git integration.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from loguru import logger

from devsecops_radar.core.path_security import (
    atomic_write,
    resolve_safe_path,
    safe_read_open,
)
from devsecops_radar.core.utils import safe_subprocess_run


# ---------------------------------------------------------------------------
# Backup directory – relative to the working directory
# ---------------------------------------------------------------------------
def _backup_dir(base_dir: Path | None = None) -> Path:
    base = (base_dir or Path.cwd()).resolve()
    d = base / ".sentinel_backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _patch_dir(base_dir: Path | None = None) -> Path:
    base = (base_dir or Path.cwd()).resolve()
    d = base / ".sentinel_patches"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------
def _sanitize_patch_content(text: str) -> str:
    """Remove ASCII control characters except newline and tab."""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)


# ---------------------------------------------------------------------------
# Backup helper
# ---------------------------------------------------------------------------
def _backup_file(target_file: str, base_dir: Path | None = None) -> Path | None:
    base = base_dir or Path.cwd()
    try:
        safe_target = resolve_safe_path(target_file, base)
    except ValueError as e:
        logger.error(f"Cannot backup unsafe path: {e}")
        return None

    if not safe_target.is_file():
        logger.warning(f"Backup skipped: file not found {safe_target}")
        return None

    backups = _backup_dir(base)
    rel_path = safe_target.relative_to(base)
    safe_name = f"{uuid.uuid4().hex}_{str(rel_path).replace(os.sep, '_')}.bak"
    backup_path = backups / safe_name

    try:
        with safe_read_open(safe_target, base_dir=base) as src:
            content = src.read()
        with atomic_write(backup_path, base_dir=backups) as dst:
            dst.write(content)
        logger.debug(f"Backed up {safe_target} to {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Backup failed for {target_file}: {e}")
        return None


# ---------------------------------------------------------------------------
# Apply a patch using the system `patch` command (safe & standard)
# ---------------------------------------------------------------------------
def _apply_patch_with_tool(original_path: Path, patch_content: str, base_dir: Path) -> bool:
    """
    Write *patch_content* to a temporary file, run `patch --dry-run` to
    verify it, and if successful, apply it to *original_path*.
    Returns True on success.
    """
    # Write patch to temp file
    try:
        fd, tmp_patch = tempfile.mkstemp(suffix=".patch", prefix="sentinel_fix_")
        with os.fdopen(fd, "w", encoding="utf-8") as pf:
            pf.write(patch_content)
    except OSError as e:
        logger.error(f"Cannot create temporary patch file: {e}")
        return False

    try:
        # Dry‑run first
        dry_run = safe_subprocess_run(
            ["patch", "--dry-run", "-p0", "-i", tmp_patch, str(original_path)],
            capture_output=True, text=True, check=False,
        )
        if dry_run.returncode != 0:
            logger.error(
                f"Patch dry‑run failed on {original_path}: {dry_run.stderr[:500]}"
            )
            return False

        # Apply for real
        result = safe_subprocess_run(
            ["patch", "-p0", "-i", tmp_patch, str(original_path)],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            logger.error(f"Patch application failed: {result.stderr[:500]}")
            return False

        logger.success(f"Patch applied successfully to {original_path}")
        return True

    except Exception as e:
        logger.error(f"Error during patching: {e}")
        return False
    finally:
        try:
            os.unlink(tmp_patch)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Main patching function
# ---------------------------------------------------------------------------
def apply_patch(
    finding: dict[str, Any],
    patch_content: str,
    base_dir: Path | None = None,
    require_evidence: bool = False,
) -> bool:
    """
    Apply *patch_content* to the file described in *finding*.

    If *require_evidence* is True, the current content of the target lines
    must match *finding.evidence* before the patch is applied.
    """
    base = base_dir or Path.cwd()
    target_file: str | None = finding.get("target")
    raw_line = finding.get("line")
    evidence = finding.get("evidence")

    if not target_file:
        logger.warning("Finding is missing 'target'. Cannot apply patch.")
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

    # Sanitize patch content
    clean_patch = _sanitize_patch_content(patch_content)
    if not clean_patch.strip():
        logger.warning("Patch content is empty after sanitization.")
        return False

    # ── Evidence check (if required or provided) ──────────────────────
    if evidence is not None:
        try:
            with safe_read_open(safe_target, base_dir=base) as f:
                original_lines = f.readlines()
            line_num = int(raw_line) if raw_line else 1
            line_index = line_num - 1
            # Extract the expected snippet from the original file
            # We don't know how many lines the evidence covers, so we compare
            # the full evidence string against a slice starting at line_index.
            # For a more precise check, the caller should provide exact length.
            end_idx = min(line_index + max(5, len(evidence.splitlines())), len(original_lines))
            current_snippet = "".join(original_lines[line_index:end_idx]).strip()
            expected_snippet = str(evidence).strip()
            if current_snippet != expected_snippet:
                logger.error(
                    f"Evidence mismatch for {safe_target} at line {line_num}. "
                    f"Expected:\n{expected_snippet!r}\nGot:\n{current_snippet!r}"
                )
                return False
            logger.info(f"Evidence matched for {safe_target}:{line_num}")
        except Exception as e:
            logger.error(f"Could not read target file for evidence check: {e}")
            return False
    else:
        if require_evidence:
            logger.warning(
                f"No evidence provided for {safe_target}. "
                "Patch skipped because evidence is required."
            )
            return False
        logger.warning(
            f"No evidence provided for {safe_target}. "
            "Patch applied without content verification – this is risky."
        )

    # Create backup before modifying
    backup_path = _backup_file(target_file, base_dir=base)
    if not backup_path:
        logger.error("Cannot proceed without a successful backup.")
        return False

    # Apply the patch using the system tool
    if not _apply_patch_with_tool(safe_target, clean_patch, base):
        # Restore from backup if the file got corrupted
        if safe_target.exists():
            try:
                shutil.copy2(str(backup_path), str(safe_target))
                logger.info(f"Restored {safe_target} from backup after failed patch.")
            except Exception as restore_err:
                logger.critical(
                    f"CRITICAL: Restore also failed! Manual intervention required for {safe_target}: {restore_err}"
                )
        return False

    logger.success(f"Successfully patched {safe_target}")
    return True


# ---------------------------------------------------------------------------
# Remediation guide & auto‑fix
# ---------------------------------------------------------------------------
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
    require_evidence: bool = True,
) -> set[str]:
    modified_files: set[str] = set()
    ai_rems = {
        r.get("finding_id"): r
        for r in ai_summary.get("top_remediations", [])
    }

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


# ---------------------------------------------------------------------------
# Git integration (PR generation)
# ---------------------------------------------------------------------------
def generate_pr(
    modified_files: set[str],
    branch: str = "sentinel-auto-fix",
    base_dir: Path | None = None,
) -> None:
    if not modified_files:
        logger.info("No files were modified. Skipping PR generation.")
        return

    if not re.match(r"^[a-zA-Z0-9_\-]+$", branch):
        logger.error(f"Invalid branch name '{branch}'. Aborting PR generation.")
        return

    base = base_dir or Path.cwd()

    # Ensure we are in a git repository
    try:
        top_level = safe_subprocess_run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Not a git repository or git not found: {e.stderr}")
        return
    except FileNotFoundError:
        logger.error("Git executable not found.")
        return

    repo_root = Path(top_level)

    # Stage the modified files
    for file in modified_files:
        try:
            safe_subprocess_run(
                ["git", "-C", str(repo_root), "add", file],
                check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stage {file}: {e.stderr}")
            return

    # Check if there is anything staged
    try:
        diff_check = safe_subprocess_run(
            ["git", "-C", str(repo_root), "diff", "--cached", "--quiet"],
            check=False, capture_output=True, text=True,
        )
        if diff_check.returncode == 0:
            logger.info("No changes to commit after staging.")
            return
    except Exception as e:
        logger.error(f"Error checking staged changes: {e}")
        return

    unique_branch = f"{branch}-{uuid.uuid4().hex[:12]}"

    try:
        current_branch_res = safe_subprocess_run(
            ["git", "-C", str(repo_root), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        original_branch = current_branch_res.stdout.strip()
    except subprocess.CalledProcessError:
        original_branch = "main"

    patches_dir = _patch_dir(base)

    try:
        safe_subprocess_run(
            ["git", "-C", str(repo_root), "checkout", "-b", unique_branch],
            check=True, capture_output=True, text=True,
        )
        safe_subprocess_run(
            ["git", "-C", str(repo_root), "commit", "-m",
             f"Security fixes applied by Pipeline Sentinel [{unique_branch}]"],
            check=True, capture_output=True, text=True,
        )

        # Attempt to push
        try:
            safe_subprocess_run(
                ["git", "-C", str(repo_root), "push", "-u", "origin", unique_branch],
                check=True, capture_output=True, text=True,
            )
            logger.success(f"✅ Pushed automated fixes to branch: {unique_branch}")
        except subprocess.CalledProcessError:
            logger.warning("Push failed — storing patch file locally for manual upload.")
            patch_file = patches_dir / f"{unique_branch}.patch"
            safe_subprocess_run(
                ["git", "-C", str(repo_root), "format-patch", "-1", "HEAD", "-o", str(patches_dir)],
                check=True, capture_output=True, text=True,
            )
            logger.info(f"Patch file saved to {patch_file}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Git operation failed during PR generation: {e.stderr}")
    except FileNotFoundError:
        logger.error("Git executable not found.")
    finally:
        # Try to return to the original branch and delete the temp branch
        try:
            safe_subprocess_run(
                ["git", "-C", str(repo_root), "checkout", original_branch],
                check=False, capture_output=True, text=True,
            )
            safe_subprocess_run(
                ["git", "-C", str(repo_root), "branch", "-D", unique_branch],
                check=False, capture_output=True, text=True,
            )
        except Exception:
            logger.warning(f"Could not clean up branch {unique_branch}")
