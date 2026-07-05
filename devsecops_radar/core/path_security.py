#Devsecops_radar/core/path_security.py

"""
Centralised secure file‑access utilities with strict TOCTOU protection
and file permission preservation.
"""

from __future__ import annotations

import errno
import os
import shutil
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
    Resolve *path* and raise ``ValueError`` if it escapes *base_dir*.

    The error message sent to the caller is generic (no internal paths).
    Full details are logged for debugging.
    """
    base = (base_dir or Path.cwd()).resolve()
    p = Path(path)
    if not p.is_absolute():
        target = (base / p).resolve()
    else:
        target = p.resolve()

    if not target.is_relative_to(base):
        logger.error(
            f"Path confinement violation: '{path}' resolves to '{target}' "
            f"which is outside the allowed base '{base}'."
        )
        raise ValueError("Path traversal attempt blocked.")
    return target


# --------------------------------------------------------------------------
# TOCTOU‑safe read – STRICTLY rejects symlinks on Unix
# --------------------------------------------------------------------------
def safe_read_open(
    path: str | Path,
    base_dir: Path | None = None,
    encoding: str = "utf-8",
) -> TextIO:
    """
    Open *path* for reading.  Symlinks are **never** followed.

    On Unix the file descriptor is obtained with ``O_NOFOLLOW``.
    If the path is a symlink, the call is rejected immediately.
    On Windows ``O_NOFOLLOW`` is 0, so the operation falls back to a
    regular open after confinement has been verified.
    """
    safe_path = resolve_safe_path(path, base_dir)

    # Use O_NOFOLLOW on Unix – if the path is a symlink we get ELOOP.
    try:
        fd = os.open(str(safe_path), os.O_RDONLY | _O_NOFOLLOW)
    except OSError as e:
        # ELOOP means the path is a symlink → reject
        if _O_NOFOLLOW and e.errno == errno.ELOOP:
            logger.error(f"Symlink not allowed: {safe_path}")
            raise ValueError("Symlink not allowed.") from e
        # Other errors (permission denied, etc.) are passed through
        raise

    # Wrap the file descriptor in a Python file object.
    # closefd=True ensures the fd is closed when the file object is closed.
    return open(fd, encoding=encoding, closefd=True)


# --------------------------------------------------------------------------
# Atomic write (race‑free, symlink‑safe, preserves original permissions)
# --------------------------------------------------------------------------
@contextmanager
def atomic_write(
    dest: str | Path,
    base_dir: Path | None = None,
    encoding: str = "utf-8",
    preserve_permissions: bool = True,
) -> Iterator[TextIO]:
    """
    Context manager that yields a writeable file object and atomically
    replaces the destination file on success.

    - The destination must be inside *base_dir*.
    - A temporary file is created in the **same directory** so that
      ``os.replace`` is atomic.
    - If *preserve_permissions* is ``True`` (the default), the original
      file's permission bits are copied to the temporary file before
      writing begins, so they are retained after the atomic replacement.
    - On exception the temporary file is removed.
    """
    safe_dest = resolve_safe_path(dest, base_dir)
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=str(safe_dest.parent), prefix=".sentinel_tmp_"
    )

    # If the destination already exists, copy its permissions to the
    # temporary file so that os.replace does not change them.
    if preserve_permissions and safe_dest.exists():
        try:
            shutil.copymode(str(safe_dest), tmp_path)
        except OSError:
            logger.warning(f"Could not copy permissions from {safe_dest} to temp file.")

    try:
        with os.fdopen(tmp_fd, "w", encoding=encoding) as f:
            yield f
        os.replace(tmp_path, str(safe_dest))
        logger.debug(f"Atomic write committed: {safe_dest}")
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
