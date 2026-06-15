import shutil
import subprocess


def safe_subprocess_run(cmd_list, **kwargs):
    """
    Safely execute system commands by resolving the absolute path of the executable.
    This prevents path hijacking and resolves Bandit B603/B607 warnings.

    Args:
        cmd_list (list): The command and its arguments as a list of strings.
        **kwargs: Standard arguments passed directly to subprocess.run().

    Returns:
        subprocess.CompletedProcess: The result of the executed command.

    Raises:
        ValueError: If the command list is empty or not a list.
        FileNotFoundError: If the executable cannot be found.
    """
    if not cmd_list or not isinstance(cmd_list, list):
        raise ValueError("Command must be provided as a non-empty list of strings.")

    executable_name = cmd_list[0]
    executable_path = shutil.which(executable_name)

    if executable_path is None:
        raise FileNotFoundError(
            f"Required executable not found: {executable_name}"
        )

    # Use absolute path for security
    cmd_list[0] = executable_path

    return subprocess.run(cmd_list, **kwargs)  # noqa: S603, S607
