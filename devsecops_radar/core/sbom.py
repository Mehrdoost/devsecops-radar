import json
import os
import subprocess


def generate_sbom(target_dir: str, output_file: str = "sbom.json") -> dict | None:
    try:
        subprocess.run(['syft', 'scan', target_dir, '-o', 'cyclonedx-json', '--output', output_file], check=True)
        with open(output_file) as f:
            return json.load(f)
    except Exception as e:
        print(f"SBOM generation failed: {e}")
        return None

def detect_dependency_confusion(manifest_path: str, internal_prefixes: list[str] = None) -> list[dict]:
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

def apply_vex_filter(findings: list[dict], vex_file: str) -> list[dict]:
    """Filter findings based on a CycloneDX VEX document."""
    if not os.path.exists(vex_file):
        return findings
    with open(vex_file) as f:
        vex = json.load(f)
    excluded = set()
    for vuln in vex.get("vulnerabilities", []):
        if vuln.get("analysis", {}).get("state") in ["not_affected", "false_positive"]:
            excluded.add(vuln.get("id"))
    return [f for f in findings if f.get("id") not in excluded]
