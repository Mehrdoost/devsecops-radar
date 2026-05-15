import json
import subprocess
import os
from pathlib import Path
from typing import List, Dict, Any

def apply_remediation(finding: Dict[str, Any], ai_fix: str) -> bool:
    """Apply a single remediation suggestion."""
    print(f"[FIX] Applying fix for {finding['id']}...")
    if 'line' in finding and finding['line']:
        # Assume we can patch the file with a git diff
        target_file = finding['target']
        if os.path.exists(target_file):
            with open(target_file, 'r') as f:
                content = f.read()
            # Simple: insert AI fix at the line (simplified; real implementation would use diff)
            lines = content.split('\n')
            line_num = finding['line'] - 1
            if line_num < len(lines):
                lines[line_num] = ai_fix
                with open(target_file, 'w') as f:
                    f.write('\n'.join(lines))
                return True
    return False

def auto_fix(findings: List[Dict[str, Any]], ai_summary: Dict[str, Any]) -> List[str]:
    """Iterate over findings and apply fixes where available."""
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

def generate_pr(findings_file: str, branch: str = "auto-fix"):
    """Attempt to create a pull request with fixes (requires git)."""
    try:
        subprocess.run(['git', 'checkout', '-b', branch], check=True)
        subprocess.run(['git', 'add', '-A'], check=True)
        subprocess.run(['git', 'commit', '-m', 'Auto-remediation by Pipeline Sentinel'], check=True)
        subprocess.run(['git', 'push', 'origin', branch], check=True)
        # Note: Creating actual PR needs GitHub CLI or API; just print instruction.
        print(f"[FIX] Branch '{branch}' pushed. Create a PR manually or via GitHub CLI.")
    except Exception as e:
        print(f"[FIX] Failed to create PR: {e}")