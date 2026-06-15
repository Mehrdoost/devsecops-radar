import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from loguru import logger

from devsecops_radar.core.utils import safe_subprocess_run

_MAX_FIELD_LENGTH = 200


def _sanitize_for_bash(value: str) -> str:
    if not isinstance(value, str):
        return ""
    value = value.replace("\n", "").replace("\r", "")
    sanitized = re.sub(r"[^a-zA-Z0-9_\-./ ]", "", value)
    return sanitized.strip()


def _cleanup_temp_dir(dir_path: str) -> None:
    try:
        shutil.rmtree(dir_path)
        logger.debug(f"Temporary directory removed: {dir_path}")
    except Exception as e:
        logger.error(f"Failed to clean up temp directory {dir_path}: {e}")


def _build_poc_script(finding_id: str, finding_title: str, target: str) -> str:
    """
    Build a dynamic Proof‑of‑Concept bash script.
    The script is safe to run inside the read‑only, network‑none sandbox.
    """
    safe_id = _sanitize_for_bash(finding_id)[:_MAX_FIELD_LENGTH]
    safe_title = _sanitize_for_bash(finding_title)[:_MAX_FIELD_LENGTH]
    safe_target = _sanitize_for_bash(target)[:_MAX_FIELD_LENGTH]

    lines = [
        "#!/bin/bash",
        "set -e",
        "echo '================== Pipeline Sentinel PoC =================='",
        f"echo 'Finding ID : {safe_id}'",
        f"echo 'Title      : {safe_title}'",
    ]

    if safe_target:
        lines.append(f"echo 'Target     : {safe_target}'")
        # If target looks like a network address, try a harmless probe
        if re.match(r"^[a-zA-Z0-9._\-]+$", safe_target) and "." in safe_target:
            lines.append("echo 'Attempting DNS lookup (will fail in sandbox)...'")
            lines.append(f"nslookup '{safe_target}' 2>&1 || true")
            lines.append("echo 'Attempting HTTP request (will fail in sandbox)...'")
            lines.append(f"curl -s -o /dev/null -w '%{{http_code}}' 'http://{safe_target}' 2>&1 || true")
        # If target looks like a file path, attempt to cat it (will be empty in sandbox)
        elif safe_target.startswith("/"):
            lines.append("echo 'Attempting file read (will fail in sandbox)...'")
            lines.append(f"cat '{safe_target}' 2>&1 || true")
        else:
            lines.append("echo 'No network or file test possible for this target type.'")
    else:
        lines.append("echo 'Target     : (none)'")

    lines.append("echo '============================================================'")
    lines.append("echo 'PoC simulation completed.'")
    return "\n".join(lines)


def simulate_attack(finding: dict) -> str:
    if not isinstance(finding, dict) or not finding.get("id") or not finding.get("title"):
        logger.error("Invalid finding data for attack simulation.")
        return _generate_dummy_script("Invalid finding data provided.")

    finding_id = str(finding.get("id"))
    finding_title = str(finding.get("title"))
    target = str(finding.get("target", ""))

    script_content = _build_poc_script(finding_id, finding_title, target)

    try:
        tmpdir = tempfile.mkdtemp(prefix="pipeline_sentinel_sim_")
        script_path = os.path.join(tmpdir, "poc.sh")
        with open(script_path, 'w') as f:
            f.write(script_content)
        os.chmod(script_path, 0o755)
        logger.debug(f"Attack simulation script created at {script_path}")
        return script_path
    except OSError as e:
        logger.error(f"Failed to write simulation script: {e}")
        return _generate_dummy_script("Script creation failed.")


def _generate_dummy_script(reason: str) -> str:
    safe_reason = _sanitize_for_bash(reason)[:_MAX_FIELD_LENGTH]
    tmpdir = tempfile.mkdtemp(prefix="pipeline_sentinel_dummy_")
    dummy_path = os.path.join(tmpdir, "poc.sh")
    with open(dummy_path, 'w') as f:
        f.write(f"#!/bin/bash\necho 'Simulation skipped: {safe_reason}'\n")
    os.chmod(dummy_path, 0o755)
    return dummy_path


def _is_docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        safe_subprocess_run(
            ["docker", "info"],
            capture_output=True,
            timeout=3,
            check=False
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def run_sandboxed_poc(script_path: str) -> str:
    if not script_path:
        logger.error("No script path provided for sandbox.")
        return "Simulation aborted: no script path."

    script_file = Path(script_path).resolve(strict=False)
    if not script_file.is_file():
        logger.error(f"Script file does not exist: {script_path}")
        return "Simulation aborted: script file not found."

    temp_root = Path(tempfile.gettempdir()).resolve()
    try:
        if not script_file.is_relative_to(temp_root):
            logger.error(f"Script {script_path} is not inside the expected temp directory.")
            return "Simulation aborted: script location is not allowed."
    except (ValueError, OSError) as e:
        logger.error(f"Path resolution error for script: {e}")
        return "Simulation aborted: invalid script path."

    real_path = os.path.realpath(script_path)
    if not os.path.commonpath([real_path, str(temp_root)]) == str(temp_root):
        logger.error("TOCTOU check failed: script path resolved outside temp directory.")
        return "Simulation aborted: script path tampering detected."

    if not _is_docker_available():
        return (
            "Docker daemon is not running or not installed. "
            "Simulation script has been generated but will not be executed."
        )

    docker_cmd = [
        "docker", "run",
        "--rm",
        "--user", "nobody",
        "--read-only",
        "--network", "none",
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        "-v", f"{script_path}:/poc.sh:ro",
        "alpine",
        "sh", "/poc.sh"
    ]

    logger.info(f"Launching sandboxed simulation: {' '.join(docker_cmd)}")

    try:
        result = safe_subprocess_run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )
    except FileNotFoundError:
        return "Docker is not installed or not running. Simulation requires Docker."
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
        return (
            f"Sandbox execution failed (exit {result.returncode}):\n{output.strip()}"
        )

    logger.success("Sandbox simulation completed successfully.")
    try:
        _cleanup_temp_dir(str(script_file.parent))
    except Exception as e:
        logger.error(f"Failed to clean up temporary directory: {e}")
    return output.strip()
