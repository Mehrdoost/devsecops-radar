import subprocess
import tempfile
import os

def simulate_attack(finding: dict) -> str:
    script = f"#!/bin/bash\n# PoC for {finding.get('id')}\necho 'Simulating {finding.get('title')}'"
    tmpdir = tempfile.mkdtemp()
    script_path = os.path.join(tmpdir, "poc.sh")
    with open(script_path, 'w') as f:
        f.write(script)
    os.chmod(script_path, 0o700)
    return script_path

def run_sandboxed_poc(script_path: str) -> str:
    try:
        result = subprocess.run(
            ['docker', 'run', '--rm', '-v', f'{script_path}:/poc.sh:ro', 'alpine', 'sh', '/poc.sh'],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception as e:
        return f"Sandbox execution failed: {e}"