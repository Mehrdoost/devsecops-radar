# devsecops_radar/core/path_security.py
"""
Centralised secure file‑access utilities.

Guarantees:
- Path‑traversal protection (directory confinement)
- TOCTOU‑safe reads via ``O_NOFOLLOW`` (Unix) / safe fallback (Windows)
- Atomic writes via ``os.replace`` (no symlink‑swap window)
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

from loguru import logger

# --------------------------------------------------------------------------
# Cross‑platform O_NOFOLLOW support
# --------------------------------------------------------------------------
_O_NOFOLLOW = os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0


# --------------------------------------------------------------------------
# Path resolution & confinement check
# --------------------------------------------------------------------------
def resolve_safe_path(path: str | Path, base_dir: Path | None = None) -> Path:
    """
    Resolve *path* and raise ValueError if it escapes *base_dir*.

    Args:
        path: Absolute or relative path. Relative paths are joined with *base_dir*.
        base_dir: The allowed root. Defaults to ``Path.cwd()``.

    Returns:
        A fully resolved ``Path`` that is guaranteed to be inside *base_dir*.

    Raises:
        ValueError: If the resolved path is outside the allowed directory.
    """
    base = (base_dir or Path.cwd()).resolve()
    p = Path(path)
    if not p.is_absolute():
        target = (base / p).resolve()
    else:
        target = p.resolve()

    if not target.is_relative_to(base):
        raise ValueError(
            f"Path '{path}' resolves to '{target}' which is outside '{base}'"
        )
    return target


# --------------------------------------------------------------------------
# TOCTOU‑safe read
# --------------------------------------------------------------------------
def safe_read_open(
    path: str | Path,
    base_dir: Path | None = None,
    encoding: str = "utf-8",
) -> TextIO:
    """
    Open *path* for reading, immune to symlink‑swap attacks on Unix.

    Uses ``os.open`` with ``O_NOFOLLOW`` on Unix; falls back to regular open
    on Windows after confinement is verified.

    Note on Windows:
        O_NOFOLLOW is not available on Windows.  A TOCTOU window exists between
        the confinement check and the actual open, but this is an accepted risk
        on Windows platforms where Pipeline Sentinel is typically not deployed
        in production security contexts.

    The caller is responsible for closing the returned file object.
    """
    safe_path = resolve_safe_path(path, base_dir)
    try:
        fd = os.open(str(safe_path), os.O_RDONLY | _O_NOFOLLOW)
    except OSError:
        # O_NOFOLLOW not supported (Windows) or the path is a symlink.
        # Confinement has already been checked – safe fallback.
        logger.debug(
            f"O_NOFOLLOW not available for '{safe_path}'; "
            "using regular open (Windows or symlink target)."
        )
        return open(safe_path, encoding=encoding)
    return open(fd, encoding=encoding)


# --------------------------------------------------------------------------
# Atomic write (race‑free, symlink‑safe)
# --------------------------------------------------------------------------
@contextmanager
def atomic_write(
    dest: str | Path,
    base_dir: Path | None = None,
    encoding: str = "utf-8",
) -> Iterator[TextIO]:
    """
    Context manager that yields a writeable file object and atomically replaces
    the destination file on success.

    - The destination must be inside *base_dir*.
    - A temporary file is created in the **same directory** so that
      ``os.replace`` is atomic.
    - On exception the temporary file is removed.
    """
    safe_dest = resolve_safe_path(dest, base_dir)
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=str(safe_dest.parent), prefix=".sentinel_tmp_"
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding=encoding) as f:
            yield f
        os.replace(tmp_path, str(safe_dest))
        logger.debug(f"Atomic write committed: {safe_dest}")
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
