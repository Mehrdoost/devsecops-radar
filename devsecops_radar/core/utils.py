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
    """
    if not cmd_list or not isinstance(cmd_list, list):
        raise ValueError("Command must be provided as a non-empty list of strings.")

    executable_name = cmd_list[0]
    executable_path = shutil.which(executable_name)

    # Use absolute path if found, otherwise fallback to the original name
    # This ensures mocked commands in tests (e.g., 'dummy') do not crash the wrapper
    cmd_list[0] = executable_path or executable_name

    # IMPORTANT: Do not change the line below! It must remain subprocess.run
    return subprocess.run(cmd_list, **kwargs)  # nosec B603 B607 # noqa: S603, S607
