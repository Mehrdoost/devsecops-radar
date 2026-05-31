import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from loguru import logger

BACKUP_DIR = Path.home() / ".devsecops-radar" / "backups"
_TRACKED_FILES: set[str] = set()


def _backup_file(target_file: str) -> None:
    backup_path = BACKUP_DIR / (Path(target_file).name + ".bak")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(target_file, backup_path)
    _TRACKED_FILES.add(target_file)


def apply_remediation(finding: dict[str, Any], ai_fix: str) -> bool:
    logger.info(f"Applying fix for {finding['id']}...")
    target_file = finding.get('target', '')
    line = finding.get('line')
    if target_file and line and os.path.exists(target_file):
        _backup_file(target_file)
        with open(target_file) as f:
            lines = f.readlines()
        line_index = line - 1
        if 0 <= line_index < len(lines):
            lines[line_index] = ai_fix + '\n'
            with open(target_file, 'w') as f:
                f.writelines(lines)
            return True
    return False


def auto_fix(findings: list[dict[str, Any]], ai_summary: dict[str, Any]) -> list[str]:
    fixed = []
    remediations = ai_summary.get('top_remediations', [])
    for rem in remediations:
        fid = rem.get('finding_id')
        action = rem.get('action', '')
        finding = next((f for f in findings if f.get('id') == fid), None)
        if finding and action:
            success = apply_remediation(finding, action)
            if success:
                fixed.append(fid)
    return fixed


def generate_fix_commands(findings: list[dict[str, Any]], ai_summary: dict[str, Any]) -> str:
    commands = []
    for rem in ai_summary.get('top_remediations', []):
        fid = rem.get('finding_id')
        action = rem.get('action', '')
        finding = next((f for f in findings if f.get('id') == fid), None)
        if finding:
            target = finding.get('target', '')
            if 'requirements.txt' in target:
                commands.append(f"# Update {target}\npip install --upgrade {finding.get('package', '')}")
            elif 'package.json' in target:
                commands.append(f"# Update {target}\nnpm update {finding.get('package', '')}")
            elif 'dockerfile' in target.lower():
                commands.append(
                    f"# Fix {target}\nsed -i "
                    f"'s/{finding.get('installed_version')}/{finding.get('fixed_version')}/' {target}"
                )
            else:
                commands.append(f"# Manual fix for {fid}: {action}")
    return '\n'.join(commands)


def generate_pr(findings_file: str, branch: str = "auto-fix") -> None:
    try:
        subprocess.run(['git', 'checkout', '-b', branch], check=True)
        if _TRACKED_FILES:
            subprocess.run(['git', 'add'] + list(_TRACKED_FILES), check=True)
        else:
            logger.warning("No files were modified; skipping PR creation.")
            return
        subprocess.run(['git', 'commit', '-m', 'Auto-remediation by Pipeline Sentinel'], check=True)
        subprocess.run(['git', 'push', 'origin', branch], check=True)
        logger.info(f"Branch '{branch}' pushed. Create a PR manually or via GitHub CLI.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create PR: {e}")
