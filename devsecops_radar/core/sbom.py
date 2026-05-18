import subprocess
import json
from typing import List, Dict, Optional

def generate_sbom(target_dir: str, output_file: str = "sbom.json") -> Optional[Dict]:
    try:
        subprocess.run(['syft', 'scan', target_dir, '-o', 'cyclonedx-json', '--output', output_file], check=True)
        with open(output_file) as f:
            return json.load(f)
    except Exception as e:
        print(f"SBOM generation failed: {e}")
        return None

def detect_dependency_confusion(manifest_path: str, internal_prefixes: List[str] = None) -> List[Dict]:
    findings = []
    if not internal_prefixes:
        internal_prefixes = ['mycompany-', 'internal-']
    try:
        with open(manifest_path) as f:
            content = f.read()
        import re
        if manifest_path.endswith('package.json'):
            pkg_pattern = re.findall(r'"([^"]+)":\s*"([^"]*)"', content)
            for name, ver in pkg_pattern:
                if any(name.startswith(p) for p in internal_prefixes):
                    findings.append({"package": name, "version": ver, "risk": "Potential dependency confusion"})
        elif manifest_path.endswith('requirements.txt'):
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    pkg = line.split('==')[0].strip()
                    if any(pkg.startswith(p) for p in internal_prefixes):
                        findings.append({"package": pkg, "version": line, "risk": "Potential dependency confusion"})
    except Exception:
        pass
    return findings