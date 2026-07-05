# devsecops_radar/core/utils.py
"""
Centralised secure subprocess runner with executable whitelisting,
directory confinement, defence‑in‑depth argument validation,
and output size capping.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

from loguru import logger

from devsecops_radar.core.path_security import resolve_safe_path

# ---------------------------------------------------------------------------
# Whitelist of allowed executables (basename → set of trusted directories)
# ---------------------------------------------------------------------------
_ALLOWED_BINARIES: dict[str, set[str]] = {
    "trivy": {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
    "semgrep": {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
    "gitleaks": {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
    "zizmor": {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
    "poutine": {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
    "ollama": {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
    "syft": {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
    "opa": {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
    "docker": {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
    "git": {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
    "nvidia-smi": {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
    "sysctl": {"/sbin", "/usr/sbin"},
}

_EXTRA_TRUSTED_DIRS: set[str] = set()
_dirs_loaded = False


def _load_extra_trusted_dirs() -> None:
    """Import settings and add any extra trusted binary directories."""
    global _EXTRA_TRUSTED_DIRS, _dirs_loaded
    if _dirs_loaded:
        return
    try:
        from devsecops_radar.core.settings import settings
        extra = settings.EXTRA_TRUSTED_BIN_DIRS
        if isinstance(extra, (list, tuple)):
            _EXTRA_TRUSTED_DIRS = set(extra)
    except Exception as e:
        logger.debug("Could not load extra trusted binary directories: {}", e)
    finally:
        _dirs_loaded = True


def _is_executable_trusted(executable: str, resolved_path: str) -> bool:
    """
    Check whether *resolved_path* is a trusted location for *executable*.
    The executable must be in the whitelist and the resolved path must lie
    inside one of the trusted directories for that binary (or the extra dirs).
    """
    # Extract base name without extension and normalize to lowercase
    base_name = os.path.basename(executable)
    base_name_no_ext = os.path.splitext(base_name)[0].lower()

    # Build a case‑insensitive lookup for whitelist keys
    allowed_keys = {k.lower(): k for k in _ALLOWED_BINARIES}
    if base_name_no_ext not in allowed_keys:
        logger.warning(f"Executable '{base_name}' (normalized: '{base_name_no_ext}') is not whitelisted.")
        return False

    original_key = allowed_keys[base_name_no_ext]
    _load_extra_trusted_dirs()
    allowed_dirs = _ALLOWED_BINARIES[original_key] | _EXTRA_TRUSTED_DIRS

    resolved = os.path.realpath(resolved_path)
    for d in allowed_dirs:
        if resolved.startswith(os.path.join(d, "")):
            return True
    logger.warning(
        f"Executable '{base_name}' resolved to '{resolved_path}' which is not "
        f"in any trusted directory. Allowed: {allowed_dirs}"
    )
    return False


# ---------------------------------------------------------------------------
# Safe subprocess runner
# ---------------------------------------------------------------------------
def safe_subprocess_run(
    cmd_list: list[str],
    *,
    timeout: float | None = None,
    capture_output: bool = False,
    text: bool = False,
    check: bool = False,
    max_output_mb: int = 0,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """
    Safely execute a system command.

    - Executable must be whitelisted **and** reside in a trusted directory.
    - ``shell=True`` is explicitly blocked.
    - Arguments that represent file paths can be automatically confined if
      passed via the *path_args* parameter (see below).
    - On timeout, the original ``TimeoutExpired`` exception is re‑raised
      **with its output and stderr preserved**.
    - If *max_output_mb* > 0, output is discarded when it exceeds this
      limit and an empty string is returned in its place.
    - All arguments are checked for shell injection patterns (``;``, ``|``, ``$``, etc.).

    Args:
        cmd_list: Command and its arguments as a list of strings.
        timeout: Passed to ``subprocess.run``.
        capture_output: If ``True``, stdout and stderr are captured.
        text: If ``True``, stdout and stderr are returned as ``str``.
        check: If ``True``, raise on non‑zero exit.
        max_output_mb: Maximum allowed size of combined stdout+stderr in megabytes.
        **kwargs: Extra keyword arguments forwarded to ``subprocess.run``
                  (``shell`` and ``executable`` are overridden).

    Returns:
        ``subprocess.CompletedProcess``

    Raises:
        ValueError: If the command list is empty, not a list,
                    if ``shell=True`` is passed,
                    or if the executable is not whitelisted/trusted.
        FileNotFoundError: If the executable is not found.
        subprocess.TimeoutExpired: If the command times out
                                   (with output/stderr intact).
    """
    if not isinstance(cmd_list, list) or not cmd_list:
        raise ValueError("Command must be a non‑empty list of strings.")

    # Explicitly block shell injection
    if kwargs.pop("shell", False):
        raise ValueError("safe_subprocess_run does not allow shell=True.")

    # Validate all arguments are strings
    for i, arg in enumerate(cmd_list):
        if not isinstance(arg, str):
            raise TypeError(f"Command argument {i} is not a string: {arg!r}")

    executable = cmd_list[0]
    # Resolve to absolute path using PATH
    resolved_path = shutil.which(executable)
    if resolved_path is None:
        raise FileNotFoundError(f"Required executable not found in PATH: {executable}")

    # Whitelist + trusted directory check
    if not _is_executable_trusted(executable, resolved_path):
        raise ValueError(
            f"Executable '{executable}' is not allowed or not in a trusted directory."
        )

    # ── Defence‑in‑depth argument validation ──────────────────────────
    # Reject arguments that contain shell meta‑characters (even though shell=False).
    _forbidden_chars = {";", "|", "&", "$", "`", "(", ")", "{", "}", "<", ">", "\n", "\r"}
    for i, arg in enumerate(cmd_list[1:], start=1):
        if any(c in arg for c in _forbidden_chars):
            raise ValueError(
                f"Argument {i} ('{arg}') contains forbidden shell characters."
            )
        # Warn if an argument looks like an option (starts with '-') and is not
        # a known file path – this is a best‑effort check.
        if arg.startswith("-") and not os.path.exists(arg):
            logger.warning(
                f"Argument {i} ('{arg}') starts with '-' and is not a file path. "
                "This may be interpreted as a command‑line option."
            )

    # ── Optional path confinement for file arguments ──────────────────
    # If the caller passes `path_args`, a list of indices (1‑based) that are
    # file paths to be confined, those arguments are resolved and validated.
    path_args = kwargs.pop("path_args", [])
    confined_cmd = [resolved_path]
    for i, arg in enumerate(cmd_list[1:], start=1):
        if i in path_args:
            try:
                safe = resolve_safe_path(arg)
                confined_cmd.append(str(safe))
            except ValueError as e:
                raise ValueError(f"Path argument {i} not allowed: {e}") from e
        else:
            confined_cmd.append(arg)

    # ── Execute ───────────────────────────────────────────────────────
    try:
        result = subprocess.run( # noqa: S603
            confined_cmd,
            timeout=timeout,
            capture_output=capture_output,
            text=text,
            check=check,
            **kwargs,
        )
    except subprocess.TimeoutExpired as e:
        # Re‑raise, preserving stdout/stderr that were captured so far
        raise subprocess.TimeoutExpired(
            cmd=confined_cmd,
            timeout=e.timeout,
            output=e.output,
            stderr=e.stderr,
        ) from e

    # Output size capping
    if max_output_mb > 0 and capture_output:
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        total_size = len(stdout.encode()) + len(stderr.encode())
        if total_size > max_output_mb * 1024 * 1024:
            logger.error(
                f"Output of command exceeds {max_output_mb}MB limit. "
                "Output discarded to prevent memory exhaustion."
            )
            result.stdout = ""
            result.stderr = f"Output exceeded {max_output_mb}MB limit."

    return result
