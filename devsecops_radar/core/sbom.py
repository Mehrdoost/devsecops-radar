import subprocess
import json
import os

def generate_sbom(target_dir: str, output_file: str = "sbom.json"):
    try:
        subprocess.run(['syft', 'scan', target_dir, '-o', 'cyclonedx-json', '--output', output_file], check=True)
        with open(output_file) as f:
            sbom = json.load(f)
        return sbom
    except Exception as e:
        print(f"SBOM generation failed: {e}")
        return None

def sbom_health(sbom: dict) -> dict:
    components = sbom.get('components', [])
    total = len(components)
    outdated = 0
    for comp in components:
        if comp.get('version', '').endswith('-SNAPSHOT'):
            outdated += 1
    return {
        "total_components": total,
        "outdated": outdated,
        "healthy": total - outdated,
        "health_percent": round((total - outdated) / total * 100, 1) if total else 0
    }