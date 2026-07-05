# devsecops_radar/core/attack_simulation.py
"""
Safe attack simulation sandbox.  No shell interpolation of user data.
All user values are sanitised and injected via a secure env‑file.
All results are returned as JSON strings so the frontend can parse them.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import NamedTuple, cast

from loguru import logger

from devsecops_radar.core.utils import safe_subprocess_run


class SimulationArtifact(NamedTuple):
    script_path: Path
    temp_dir: Path
    finding_id: str
    finding_title: str
    target: str


# ---------------------------------------------------------------------------
# Sanitize a string so that it cannot break Docker env‑file or shell
# ---------------------------------------------------------------------------
def _sanitize_env_value(s: str) -> str:
    """Remove characters that could be interpreted as Docker options or
    shell metacharacters when passed through an env‑file."""
    if not isinstance(s, str):
        return ""
    # Remove null bytes, newlines, carriage returns, and common injection chars
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", s)
    # Remove backticks, dollar signs, parentheses, braces, pipes, semicolons
    for ch in ("`", "$", "(", ")", "{", "}", "|", ";", "&", "'", '"', "\\"):
        s = s.replace(ch, "")
    # Collapse multiple whitespace into single space
    s = re.sub(r"\s+", " ", s).strip()
    return s


# ---------------------------------------------------------------------------
# Static PoC script – completely static, no user data embedded
# ---------------------------------------------------------------------------
_POC_SCRIPT = r"""#!/bin/sh
echo '================== Pipeline Sentinel PoC =================='
echo "Finding ID : $FINDING_ID"
echo "Title      : $FINDING_TITLE"
echo "Target     : $FINDING_TARGET"
echo '============================================================'
echo 'PoC simulation completed (safe static script).'
"""


def simulate_attack(finding: dict) -> SimulationArtifact | None:
    if not isinstance(finding, dict) or not finding.get("id") or not finding.get("title"):
        logger.error("Invalid finding data for attack simulation.")
        return None

    finding_id = _sanitize_env_value(str(finding.get("id")))
    finding_title = _sanitize_env_value(str(finding.get("title")))
    target = _sanitize_env_value(str(finding.get("target", "")))

    try:
        tmpdir = Path(tempfile.mkdtemp(prefix="pipeline_sentinel_sim_"))
        script_path = tmpdir / "poc.sh"
        script_path.write_text(_POC_SCRIPT, encoding="utf-8")
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
    """Return True if Docker is installed and the daemon is reachable."""
    # First, check if the docker binary exists at all (without using safe_subprocess_run
    # so that we don't hit the whitelist problem on Windows).
    docker_path = shutil.which("docker")
    if not docker_path:
        logger.info("Docker not found in PATH.")
        return False

    # Optionally, try a lightweight check to confirm the daemon is running.
    # safe_subprocess_run will perform its own whitelist verification,
    # but by now we already know that 'docker' is in PATH.
    try:
        safe_subprocess_run(
            [docker_path, "info"], capture_output=True, timeout=3, check=False
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError) as e:
        logger.warning(f"Docker daemon is not running or not accessible: {e}")
        return False


def run_sandboxed_poc(artifact: SimulationArtifact) -> str:
    """Execute the PoC inside Docker and return a JSON‑serialised result.

    The return value is always a JSON string containing either a
    ``script``/``sandbox_output`` pair (on success) or an ``error`` key
    (on failure).  The frontend is responsible for parsing it.
    """
    script_path = artifact.script_path
    temp_dir = artifact.temp_dir

    if not script_path.is_file():
        logger.error(f"Script file does not exist: {script_path}")
        return json.dumps({"error": "Simulation aborted: script file not found."})

    # Confinement check
    try:
        script_path.resolve().relative_to(temp_dir.resolve())
    except ValueError:
        logger.error(f"Script {script_path} is outside expected temp dir {temp_dir}")
        return json.dumps({"error": "Simulation aborted: script location not allowed."})

    if not _is_docker_available():
        return json.dumps(
            {
                "error": (
                    "Docker is not installed or not running. "
                    "Please install Docker to run attack simulations."
                )
            }
        )

    # Write env‑file to avoid passing values on the command line directly
    env_file = temp_dir / ".env_sim"
    try:
        env_lines = [
            f"FINDING_ID={artifact.finding_id}\n",
            f"FINDING_TITLE={artifact.finding_title}\n",
            f"FINDING_TARGET={artifact.target}\n",
        ]
        env_file.write_text("".join(env_lines), encoding="utf-8")
    except OSError as e:
        logger.error(f"Cannot write env‑file: {e}")
        return json.dumps({"error": "Simulation aborted: cannot create environment file."})

    docker_cmd = [
        "docker", "run", "--rm",
        "--user", "nobody",
        "--read-only",
        "--network", "none",
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        "-v", f"{script_path}:/poc.sh:ro",
        "--env-file", str(env_file),
        "alpine", "sh", "/poc.sh",
    ]

    logger.info(f"Launching sandboxed simulation: {' '.join(docker_cmd)}")

    try:
        result = safe_subprocess_run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            max_output_mb=10,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed."})
    except subprocess.TimeoutExpired as e:
        logger.error("Sandbox simulation timed out.")
        stdout = cast(str, e.output or "")
        stderr = cast(str, e.stderr or "")
        return json.dumps(
            {
                "error": "Simulation timed out.",
                "partial_output": stdout + stderr,
            }
        )
    except Exception as e:
        logger.error(f"Unexpected error during sandbox execution: {e}")
        return json.dumps({"error": f"Sandbox execution failed: {str(e)}"})

    stdout = cast(str, result.stdout or "")
    stderr = cast(str, result.stderr or "")
    output = stdout + stderr
    if result.returncode != 0:
        logger.warning(
            f"Docker sandbox exited with code {result.returncode}: {output.strip()}"
        )
        return json.dumps(
            {
                "error": f"Sandbox execution failed (exit {result.returncode}).",
                "output": output.strip(),
            }
        )

    logger.success("Sandbox simulation completed successfully.")

    # Clean up temp dir completely
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.debug(f"Temporary directory removed: {temp_dir}")
    except Exception as e:
        logger.error(f"Failed to clean up temp directory {temp_dir}: {e}")

    return json.dumps(
        {
            "script": _POC_SCRIPT,
            "sandbox_output": output.strip(),
        }
    )
