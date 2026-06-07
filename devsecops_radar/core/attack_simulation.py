import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from loguru import logger


def _sanitize_for_bash(value: str) -> str:
    """
    Escape a string so that it can be safely placed inside single quotes in a bash script.
    The only character that cannot appear inside a single-quoted string is the single quote itself.
    We replace each ' with '\'' (end current quoting, add escaped quote, resume quoting).
    """
    return value.replace("'", "'\\''")


def _cleanup_temp_dir(dir_path: str) -> None:
    """Securely remove a temporary directory and its contents."""
    try:
        shutil.rmtree(dir_path)
        logger.debug(f"Temporary directory removed: {dir_path}")
    except Exception as e:
        logger.error(f"Failed to clean up temp directory {dir_path}: {e}")


def simulate_attack(finding: dict) -> str:
    """
    Generate a safe proof-of-concept script for a given finding.
    The script echoes the finding's title and ID safely.
    Returns the path to the generated script.
    """
    if not isinstance(finding, dict) or not finding.get("id") or not finding.get("title"):
        logger.error("Invalid finding data for attack simulation.")
        return _generate_dummy_script("Invalid finding data provided.")

    finding_id = _sanitize_for_bash(str(finding.get("id")))
    finding_title = _sanitize_for_bash(str(finding.get("title")))

    script_content = (
        "#!/bin/bash\n"
        f"# PoC for {finding_id}\n"
        f"echo 'Simulating {finding_title}'\n"
    )

    try:
        # Create a secure temporary directory with a recognizable prefix
        tmpdir = tempfile.mkdtemp(prefix="pipeline_sentinel_sim_")
        script_path = os.path.join(tmpdir, "poc.sh")

        # Write script and set restrictive permissions (owner read+execute only)
        with open(script_path, 'w') as f:
            f.write(script_content)
        os.chmod(script_path, 0o500)

        logger.debug(f"Attack simulation script created at {script_path}")
        return script_path

    except OSError as e:
        logger.error(f"Failed to write simulation script: {e}")
        return _generate_dummy_script("Script creation failed.")


def _generate_dummy_script(reason: str) -> str:
    """Generate a harmless dummy script when input is invalid."""
    tmpdir = tempfile.mkdtemp(prefix="pipeline_sentinel_dummy_")
    dummy_path = os.path.join(tmpdir, "poc.sh")
    safe_reason = _sanitize_for_bash(reason)
    with open(dummy_path, 'w') as f:
        f.write(f"#!/bin/bash\necho 'Simulation skipped: {safe_reason}'\n")
    os.chmod(dummy_path, 0o500)
    return dummy_path


def run_sandboxed_poc(script_path: str) -> str:
    """
    Execute the PoC script inside a disposable, hardened Docker container.
    The script is mounted read-only, the container runs without network,
    with all capabilities dropped, as a non-root user.
    Returns the sandbox output or an error message.
    """
    # --- Path Validation ---
    if not script_path:
        logger.error("No script path provided for sandbox.")
        return "Simulation aborted: no script path."

    script_file = Path(script_path)
    if not script_file.is_file():
        logger.error(f"Script file does not exist: {script_path}")
        return "Simulation aborted: script file not found."

    # The script must reside in a standard temp directory to prevent arbitrary file reads
    temp_root = Path(tempfile.gettempdir()).resolve()
    try:
        if not script_file.resolve().is_relative_to(temp_root):
            logger.error(f"Script {script_path} is not inside the expected temp directory.")
            return "Simulation aborted: script location is not allowed."
    except (ValueError, OSError) as e:
        logger.error(f"Path resolution error for script: {e}")
        return "Simulation aborted: invalid script path."

    # Ensure the script path does not contain characters that could break Docker volume mounting (e.g., ':')
    if ":" in script_path:
        logger.error(f"Script path contains invalid character ':' – {script_path}")
        return "Simulation aborted: invalid characters in script path."

    # --- Docker Availability Check ---
    if not shutil.which("docker"):
        logger.warning("Docker not found in PATH.")
        return "Docker is not installed or not running. Simulation requires Docker."

    # --- Build Secure Docker Command ---
    # We use a list of arguments – no shell involvement.
    docker_cmd = [
        "docker", "run",
        "--rm",
        "--user", "nobody",                   # run as unprivileged user
        "--read-only",                         # root filesystem read-only
        "--network", "none",                   # no network access
        "--security-opt", "no-new-privileges", # prevent privilege escalation
        "--cap-drop", "ALL",                   # drop all kernel capabilities
        "-v", f"{script_path}:/poc.sh:ro",     # mount script as read-only
        "alpine",                              # minimal image
        "sh", "/poc.sh"
    ]

    # Optional: use shlex.quote on the script path for extra safety (though list-based args already protect)
    # docker_cmd[8] = f"{shlex.quote(script_path)}:/poc.sh:ro"  # unnecessary but doesn't hurt
    # We'll keep the original because the path is already validated and list args prevent injection.

    logger.info(f"Launching sandboxed simulation: {' '.join(docker_cmd)}")

    try:
        result = subprocess.run(
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
        logger.warning(f"Docker sandbox exited with code {result.returncode}: {output.strip()}")
        return f"Sandbox execution failed (exit {result.returncode}):\n{output.strip()}"

    logger.success("Sandbox simulation completed successfully.")
    # Clean up the temporary directory after successful execution
    _cleanup_temp_dir(script_file.parent)
    return output.strip()
