# devsecops_radar/core/attack_simulation.py
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import NamedTuple

from loguru import logger

from devsecops_radar.core.utils import safe_subprocess_run


class SimulationArtifact(NamedTuple):
    """Container for everything needed to run a sandboxed PoC."""
    script_path: Path
    temp_dir: Path
    finding_id: str
    finding_title: str
    target: str


def simulate_attack(finding: dict) -> SimulationArtifact | None:
    """
    Create a safe PoC script and return its location together with
    the finding metadata.

    The script itself is static – all dynamic content is passed via
    environment variables at runtime.  This eliminates command‑injection
    risks while preserving the realistic probe behaviour.
    """
    if not isinstance(finding, dict) or not finding.get("id") or not finding.get("title"):
        logger.error("Invalid finding data for attack simulation.")
        return None

    finding_id = str(finding.get("id"))
    finding_title = str(finding.get("title"))
    target = str(finding.get("target", ""))

    # Static script – probes are enabled but all user data comes from env vars.
    script = r"""#!/bin/bash
set -e

echo '================== Pipeline Sentinel PoC =================='
echo "Finding ID : $FINDING_ID"
echo "Title      : $FINDING_TITLE"
echo "Target     : $FINDING_TARGET"

if [ -n "$FINDING_TARGET" ]; then
    # Heuristic probes – all will safely fail inside the locked‑down sandbox.
    if [[ "$FINDING_TARGET" =~ ^[a-zA-Z0-9._-]+$ ]] && [[ "$FINDING_TARGET" == *"."* ]]; then
        echo 'Attempting DNS lookup (will fail in sandbox)...'
        nslookup "$FINDING_TARGET" 2>&1 || true
        echo 'Attempting HTTP request (will fail in sandbox)...'
        curl -s -o /dev/null -w '%{http_code}' "http://$FINDING_TARGET" 2>&1 || true
    elif [[ "$FINDING_TARGET" == /* ]]; then
        echo 'Attempting file read (will fail in sandbox)...'
        cat "$FINDING_TARGET" 2>&1 || true
    else
        echo 'No network or file test possible for this target type.'
    fi
else
    echo 'Target     : (none)'
fi

echo '============================================================'
echo 'PoC simulation completed.'
"""

    try:
        tmpdir = Path(tempfile.mkdtemp(prefix="pipeline_sentinel_sim_"))
        script_path = tmpdir / "poc.sh"
        script_path.write_text(script, encoding="utf-8")
        script_path.chmod(0o755)
        logger.debug(f"Attack simulation script created at {script_path}")
        return SimulationArtifact(
            script_path=script_path,
            temp_dir=tmpdir,
            finding_id=finding_id,
            finding_title=finding_title,
            target=target,
        )
    except OSError as e:
        logger.error(f"Failed to create simulation script: {e}")
        return None


def _is_docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        safe_subprocess_run(
            ["docker", "info"], capture_output=True, timeout=3, check=False
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def run_sandboxed_poc(artifact: SimulationArtifact) -> str:
    """
    Execute the PoC script inside a locked‑down Docker container.
    Confinement is verified against *artifact.temp_dir*.
    """
    script_path = artifact.script_path
    temp_dir = artifact.temp_dir

    if not script_path.is_file():
        logger.error(f"Script file does not exist: {script_path}")
        return "Simulation aborted: script file not found."

    # Confinement: script MUST be inside the specific temp_dir
    try:
        script_path.resolve().relative_to(temp_dir.resolve())
    except ValueError:
        logger.error(
            f"Script {script_path} is outside expected temp dir {temp_dir}"
        )
        return "Simulation aborted: script location not allowed."

    if not _is_docker_available():
        return (
            "Docker is not available. "
            "Simulation script has been generated but not executed."
        )

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--user", "nobody",
        "--read-only",
        "--network", "none",
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        "-v", f"{script_path}:/poc.sh:ro",
        "-e", f"FINDING_ID={artifact.finding_id}",
        "-e", f"FINDING_TITLE={artifact.finding_title}",
        "-e", f"FINDING_TARGET={artifact.target}",
        "alpine",
        "sh", "/poc.sh",
    ]

    logger.info(f"Launching sandboxed simulation: {' '.join(docker_cmd)}")

    try:
        result = safe_subprocess_run(
            docker_cmd, capture_output=True, text=True, timeout=30, check=False
        )
    except FileNotFoundError:
        return "Docker is not installed."
    except subprocess.TimeoutExpired:
        logger.error("Sandbox simulation timed out.")
        return "Simulation timed out after 30 seconds."
    except Exception as e:
        logger.error(f"Unexpected error during sandbox execution: {e}")
        return f"Sandbox execution failed: {str(e)}"

    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        logger.warning(
            f"Docker sandbox exited with code {result.returncode}: {output.strip()}"
        )
        return f"Sandbox execution failed (exit {result.returncode}):\n{output.strip()}"

    logger.success("Sandbox simulation completed successfully.")

    # Clean up the temporary directory
    try:
        shutil.rmtree(temp_dir)
        logger.debug(f"Temporary directory removed: {temp_dir}")
    except Exception as e:
        logger.error(f"Failed to clean up temp directory {temp_dir}: {e}")

    return output.strip()
