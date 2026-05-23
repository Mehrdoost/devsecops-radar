import os
import subprocess
import tempfile


def simulate_attack(finding: dict) -> str:
    """
    Generate a simple proof-of-concept script for a given finding.
    Returns the path to the script.
    """
    script = (
        f"#!/bin/bash\n"
        f"# PoC for {finding.get('id')}\n"
        f"echo 'Simulating {finding.get('title')}'\n"
    )
    tmpdir = tempfile.mkdtemp()
    script_path = os.path.join(tmpdir, "poc.sh")
    with open(script_path, 'w') as f:
        f.write(script)
    os.chmod(script_path, 0o700)
    return script_path


def run_sandboxed_poc(script_path: str) -> str:
    """
    Execute the PoC script inside a disposable Docker container.
    If Docker is not available, return a clear message.
    """
    try:
        result = subprocess.run(
            [
                'docker', 'run', '--rm',
                '-v', f'{script_path}:/poc.sh:ro',
                'alpine', 'sh', '/poc.sh'
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout if result.stdout else result.stderr
    except FileNotFoundError:
        return "Docker is not installed or not running. Simulation requires Docker."
    except subprocess.TimeoutExpired:
        return "Simulation timed out after 30 seconds."
    except Exception as e:
        return f"Sandbox execution failed: {e}"
