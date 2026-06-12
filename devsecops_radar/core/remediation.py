import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from loguru import logger

# Secure backup directory – now under user home, as promised in the README
BACKUP_DIR = Path.home() / ".devsecops-radar" / "backups"


def _init_backup_dir() -> None:
    """Ensure the backup directory exists (idempotent)."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _is_safe_path(target_file: str, base_dir: Path | None = None) -> bool:
    """
    Prevents Path Traversal attacks.
    Ensures the target file is strictly within the allowed base directory.
    """
    if base_dir is None:
        base_dir = Path.cwd()

    try:
        abs_target = Path(target_file).resolve(strict=False)
        return abs_target.is_relative_to(base_dir.resolve())
    except Exception as e:
        logger.error(f"Path resolution error for {target_file}: {e}")
        return False


def _backup_file(target_file: str) -> Path | None:
    """Creates a backup of the file before any modification."""
    _init_backup_dir()
    source_path = Path(target_file)

    if not source_path.exists():
        return None

    # Use a unique name that includes the relative path to avoid collisions
    # Replace path separators with underscores for a flat backup directory
    try:
        rel_path = source_path.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        rel_path = source_path.name
    safe_name = str(rel_path).replace(os.sep, "_") + ".bak"
    backup_path = BACKUP_DIR / safe_name

    try:
        shutil.copy2(source_path, backup_path)
        logger.debug(f"Backed up {source_path} to {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Backup failed for {target_file}: {e}")
        return None


def apply_patch(
    finding: dict[str, Any],
    patch_content: str,
    base_dir: Path | None = None,
) -> bool:
    """
    Safely applies a string patch/fix to a specific line in a file.
    The patch is forced to be a single line to prevent code injection.
    """
    target_file = finding.get("target", "")
    raw_line = finding.get("line")

    if not target_file or raw_line is None:
        logger.warning("Finding is missing 'target' or 'line'. Cannot apply patch.")
        return False

    try:
        line_num = int(raw_line)
    except ValueError:
        logger.error(f"Invalid line number format: {raw_line}")
        return False

    if not _is_safe_path(target_file, base_dir):
        logger.error(
            f"Security Error: Target {target_file} is outside the allowed directory."
        )
        return False

    target_path = Path(target_file)
    if not target_path.exists():
        logger.error(f"Target file does not exist: {target_file}")
        return False

    backup_path = _backup_file(target_file)
    if not backup_path:
        return False

    # --- Strict patch sanitization ---
    # Remove all line breaks completely to force a single line.
    # This eliminates any chance of injecting extra commands or lines.
    safe_patch = patch_content.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    safe_patch = safe_patch.strip() + "\n"

    temp_fd = -1
    temp_path = None
    try:
        # Atomic Write Pattern
        temp_fd, temp_path = tempfile.mkstemp(
            dir=target_path.parent, text=True
        )
        with open(target_path, encoding="utf-8") as f:
            lines = f.readlines()

        line_index = line_num - 1
        if 0 <= line_index < len(lines):
            lines[line_index] = safe_patch
        else:
            logger.error(
                f"Line number {line_num} is out of bounds for {target_file}"
            )
            return False

        # Write to temp file
        with os.fdopen(temp_fd, "w", encoding="utf-8") as tf:
            tf.writelines(lines)
        temp_fd = -1  # ownership transferred to fdopen

        # Atomic replace
        os.replace(temp_path, target_path)
        logger.info(f"Successfully patched {target_file} at line {line_num}")
        return True

    except Exception as e:
        logger.error(f"Failed to apply patch to {target_file}: {e}")
        # Rollback on failure
        if backup_path and backup_path.exists():
            shutil.copy2(backup_path, target_path)
            logger.info(f"Rolled back {target_file} from backup.")
        return False
    finally:
        # Guaranteed cleanup of temp resources
        if temp_fd != -1:
            try:
                os.close(temp_fd)
            except Exception:
                pass
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


def generate_remediation_guide(
    ai_remediations: list[dict[str, Any]],
) -> str:
    """
    Converts the AI's safe 'remediation_steps' into a human-readable CLI guide.
    Replaces the dangerous 'generate_fix_commands' function.
    """
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
) -> set[str]:
    """
    Attempts to apply automated patches and returns a set of modified files.
    """
    modified_files = set()
    ai_rems = {
        r.get("finding_id"): r
        for r in ai_summary.get("top_remediations", [])
    }

    for f in findings:
        fid = f.get("id")
        if fid in ai_rems:
            patch = ai_rems[fid].get("patch_content")
            if patch and apply_patch(f, patch):
                modified_files.add(f.get("target"))

    return modified_files


def generate_pr(
    modified_files: set[str],
    branch: str = "sentinel-auto-fix",
) -> None:
    """
    Commits modified files and creates a PR branch.
    Strictly validates branch names to prevent command injection.
    """
    if not modified_files:
        logger.info("No files were modified. Skipping PR generation.")
        return

    # Security: Strict Branch Name Validation (Anti Command Injection)
    if not re.match(r"^[a-zA-Z0-9_\-]+$", branch):
        logger.error(
            f"Invalid branch name '{branch}'. Aborting PR generation."
        )
        return

    try:
        subprocess.run(
            ["git", "checkout", "-b", branch],
            check=True, capture_output=True, text=True,
        )

        for file in modified_files:
            subprocess.run(
                ["git", "add", file],
                check=True, capture_output=True, text=True,
            )

        subprocess.run(
            ["git", "commit", "-m",
             "Security Fixes applied by Pipeline Sentinel"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["git", "push", "-u", "origin", branch],
            check=True, capture_output=True, text=True,
        )
        logger.info(
            f"✅ Successfully pushed automated fixes to branch: {branch}"
        )

    except subprocess.CalledProcessError as e:
        logger.error(f"Git operation failed during PR generation:\n{e.stderr}")
    except FileNotFoundError:
        logger.error("Git executable not found. Ensure git is installed.")
