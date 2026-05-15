import os
import subprocess
from typing import List, Dict, Any

def apply_remediation(finding: Dict[str, Any], ai_fix: str) -> bool:
    print(f"[FIX] Applying fix for {finding['id']}...")
    target_file = finding.get('target', '')
    line = finding.get('line')
    if target_file and line and os.path.exists(target_file):
        with open(target_file, 'r') as f:
            lines = f.readlines()
        line_index = line - 1
        if 0 <= line_index < len(lines):
            lines[line_index] = ai_fix + '\n'
            with open(target_file, 'w') as f:
                f.writelines(lines)
            return True
    return False

def auto_fix(findings: List[Dict[str, Any]], ai_summary: Dict[str, Any]) -> List[str]:
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

def generate_fix_commands(findings: List[Dict[str, Any]], ai_summary: Dict[str, Any]) -> str:
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
                commands.append(f"# Fix {target}\nsed -i 's/{finding.get('installed_version')}/{finding.get('fixed_version')}/' {target}")
            else:
                commands.append(f"# Manual fix for {fid}: {action}")
    return '\n'.join(commands)

def generate_pr(findings_file: str, branch: str = "auto-fix"):
    try:
        subprocess.run(['git', 'checkout', '-b', branch], check=True)
        subprocess.run(['git', 'add', '-A'], check=True)
        subprocess.run(['git', 'commit', '-m', 'Auto-remediation by Pipeline Sentinel'], check=True)
        subprocess.run(['git', 'push', 'origin', branch], check=True)
        print(f"[FIX] Branch '{branch}' pushed. Create a PR manually or via GitHub CLI.")
    except Exception as e:
        print(f"[FIX] Failed to create PR: {e}")