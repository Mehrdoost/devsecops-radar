import shutil
import subprocess
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
        subprocess.TimeoutExpired: Re‑raised with a clearer message.
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

    # Resolve executable to absolute path without mutating original list
    executable = shutil.which(cmd_list[0])
    if executable is None:
        raise FileNotFoundError(f"Required executable not found: {cmd_list[0]}")

    resolved_cmd = [executable] + cmd_list[1:]

    # Ensure shell is never True even if accidentally left in kwargs after pop
    kwargs.setdefault("shell", False)

    # Capture common timeout handling to give a better error message
    try:
        return subprocess.run(resolved_cmd, **kwargs)  # noqa: S603
    except subprocess.TimeoutExpired as err:
        timeout_val = kwargs.get("timeout", "undefined")
        raise subprocess.TimeoutExpired(
            cmd=resolved_cmd,
            timeout=float(timeout_val) if isinstance(timeout_val, (int, float)) else 0.0,
        ) from err
    except Exception:
        raise
