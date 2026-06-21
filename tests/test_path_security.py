"""Tests for centralized path security utilities – Windows‑safe version."""

import sys
from unittest.mock import patch

import pytest

from devsecops_radar.core.path_security import (
    atomic_write,
    resolve_safe_path,
    safe_read_open,
)


# ---------------------------------------------------------------------------
# resolve_safe_path
# ---------------------------------------------------------------------------
class TestResolveSafePath:
    def test_relative_path_inside_base(self, tmp_path):
        p = resolve_safe_path("sub/file.txt", tmp_path)
        assert p == (tmp_path / "sub/file.txt").resolve()

    def test_absolute_path_inside_base(self, tmp_path):
        f = tmp_path / "inside.txt"
        f.touch()
        p = resolve_safe_path(str(f), tmp_path)
        assert p == f.resolve()

    def test_relative_path_default_cwd(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        p = resolve_safe_path("file.txt")
        assert p == (tmp_path / "file.txt").resolve()

    def test_traversal_raises(self, tmp_path):
        with pytest.raises(ValueError, match="outside"):
            resolve_safe_path("../etc/passwd", tmp_path)

    def test_absolute_path_outside_base_raises(self, tmp_path):
        outside = tmp_path.parent / "outside.txt"
        with pytest.raises(ValueError, match="outside"):
            resolve_safe_path(str(outside), tmp_path)

    @pytest.mark.skipif(
        sys.platform == "win32", reason="symlink creation requires administrator privileges"
    )
    def test_resolves_symlinks(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        target = base / "target.txt"
        target.write_text("data")
        link = base / "link.txt"
        link.symlink_to(target)
        p = resolve_safe_path(str(link), base)
        assert p == target.resolve()
        assert p.is_relative_to(base)

    @pytest.mark.skipif(
        sys.platform == "win32", reason="symlink creation requires administrator privileges"
    )
    def test_path_outside_via_symlink_raises(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        outside = tmp_path / "outside.txt"
        outside.touch()
        link = base / "link.txt"
        link.symlink_to(outside)
        with pytest.raises(ValueError, match="outside"):
            resolve_safe_path(str(link), base)


# ---------------------------------------------------------------------------
# safe_read_open
# ---------------------------------------------------------------------------
class TestSafeReadOpen:
    def test_reads_file_content(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_text("hello")
        with safe_read_open(f, base_dir=tmp_path) as fh:
            assert fh.read() == "hello"

    def test_raises_value_error_if_path_outside(self, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.touch()
        with pytest.raises(ValueError, match="outside"):
            safe_read_open("../outside.txt", base_dir=tmp_path)

    def test_returns_file_like_object(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("data")
        obj = safe_read_open(f, base_dir=tmp_path)
        assert obj.read() == "data"
        obj.close()

    @patch("devsecops_radar.core.path_security._O_NOFOLLOW", 0)
    def test_windows_fallback_when_ono_follow_missing(self, tmp_path):
        f = tmp_path / "win.txt"
        f.write_text("windows")
        with patch("os.open", side_effect=OSError("No O_NOFOLLOW")), \
             patch("devsecops_radar.core.path_security.logger") as mock_log:
            with safe_read_open(f, base_dir=tmp_path) as fh:
                assert fh.read() == "windows"
            mock_log.debug.assert_called_once()
            assert "O_NOFOLLOW not available" in mock_log.debug.call_args[0][0]


# ---------------------------------------------------------------------------
# atomic_write
# ---------------------------------------------------------------------------
class TestAtomicWrite:
    def test_writes_file_atomically(self, tmp_path):
        dest = tmp_path / "output.txt"
        content = "atomic content"
        with atomic_write(dest, base_dir=tmp_path) as f:
            f.write(content)
        assert dest.read_text() == content
        temps = list(tmp_path.glob(".sentinel_tmp_*"))
        assert len(temps) == 0

    def test_cleans_up_on_exception(self, tmp_path):
        dest = tmp_path / "output.txt"
        with pytest.raises(RuntimeError):
            with atomic_write(dest, base_dir=tmp_path) as f:
                f.write("partial")
                raise RuntimeError("fail")
        assert not dest.exists()
        temps = list(tmp_path.glob(".sentinel_tmp_*"))
        assert len(temps) == 0

    def test_replaces_existing_file(self, tmp_path):
        dest = tmp_path / "output.txt"
        dest.write_text("old")
        with atomic_write(dest, base_dir=tmp_path) as f:
            f.write("new")
        assert dest.read_text() == "new"

    def test_writes_to_existing_subdirectory(self, tmp_path):
        # atomic_write does NOT create parent directories; test ensures parent exists
        subdir = tmp_path / "sub"
        subdir.mkdir()
        dest = subdir / "output.txt"
        with atomic_write(dest, base_dir=tmp_path) as f:
            f.write("nested")
        assert dest.read_text() == "nested"

    def test_raises_if_dest_outside_base(self, tmp_path):
        outside = tmp_path.parent / "out.txt"
        with pytest.raises(ValueError, match="outside"):
            with atomic_write(str(outside), base_dir=tmp_path):
                pass

    def test_writes_with_custom_encoding(self, tmp_path):
        dest = tmp_path / "enc.txt"
        with atomic_write(dest, base_dir=tmp_path, encoding="utf-16") as f:
            f.write("hello")
        assert dest.read_text(encoding="utf-16") == "hello"

    def test_logs_debug_on_success(self, tmp_path):
        dest = tmp_path / "debug.txt"
        with patch("devsecops_radar.core.path_security.logger") as mock_log:
            with atomic_write(dest, base_dir=tmp_path) as f:
                f.write("ok")
        mock_log.debug.assert_called_once()
        assert "Atomic write committed" in mock_log.debug.call_args[0][0]
