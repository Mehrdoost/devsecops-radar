# devsecops_radar/core/utils.py
import shutil
import subprocess
from pathlib import Path
from typing import Any


def safe_subprocess_run(cmd_list: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """
    Safely execute system commands by resolving the absolute path of the executable.
    This prevents path hijacking and explicitly blocks shell=True.

    Args:
        cmd_list: The command and its arguments as a list of strings.
        **kwargs: Passed to subprocess.run(), except 'shell' which is forced to False.

    Returns:
        subprocess.CompletedProcess

    Raises:
        ValueError: If command list is empty, not a list, or contains non-strings.
        ValueError: If shell=True is passed.
        FileNotFoundError: If executable not found.
        subprocess.TimeoutExpired: If the command times out (when a timeout is given).
    """
    if not isinstance(cmd_list, list) or not cmd_list:
        raise ValueError("Command must be a non‑empty list of strings.")

    # Block shell injection vector entirely
    if kwargs.pop("shell", False):
        raise ValueError("safe_subprocess_run does not allow shell=True.")

    # Validate all arguments are strings
    for i, arg in enumerate(cmd_list):
        if not isinstance(arg, str):
            raise TypeError(f"Command argument {i} is not a string: {arg!r}")

    # Resolve executable to absolute path.
    # If the first argument looks like a local path (contains '/' or '\'),
    # first check if it's an executable file directly.
    executable = cmd_list[0]
    if any(c in executable for c in ("/", "\\")):
        # It's a path – resolve it relative to cwd
        resolved_path = Path(executable).resolve()
        if not resolved_path.is_file():
            # Fall back to PATH search (in case it's a bare filename with slash)
            found = shutil.which(executable)
            if found:
                executable = found
            else:
                raise FileNotFoundError(f"Executable not found: {executable}")
        else:
            executable = str(resolved_path)
    else:
        # Simple name – search PATH
        found = shutil.which(cmd_list[0])
        if found is None:
            raise FileNotFoundError(f"Required executable not found: {cmd_list[0]}")
        executable = found

    resolved_cmd = [executable] + cmd_list[1:]

    # Ensure shell is never True even if accidentally left in kwargs after pop
    kwargs.setdefault("shell", False)

    # Capture common timeout handling to give a better error message
    try:
        return subprocess.run(resolved_cmd, **kwargs)  # nosec B603 B607  # noqa: S603, S607
    except subprocess.TimeoutExpired as err:
        timeout_val = kwargs.get("timeout", "undefined")
        raise subprocess.TimeoutExpired(
            cmd=resolved_cmd,
            timeout=float(timeout_val) if isinstance(timeout_val, (int, float)) else 0.0,
        ) from err
    except Exception:
        raise   # noqa: B904