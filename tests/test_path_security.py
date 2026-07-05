"""Tests for path security – updated for generic error messages."""

from contextlib import contextmanager

import pytest

from devsecops_radar.core.path_security import (
    atomic_write,
    resolve_safe_path,
    safe_read_open,
)


# ---------------------------------------------------------------------------
# Helper to capture loguru output
# ---------------------------------------------------------------------------
@contextmanager
def capture_loguru(level="TRACE"):
    from loguru import logger
    messages = []
    def sink(msg):
        messages.append(str(msg))
    handler_id = logger.add(sink, level=level, format="{message}")
    try:
        yield messages
    finally:
        logger.remove(handler_id)


class TestResolveSafePath:
    def test_relative_path_inside_base(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        (base / "file.txt").touch()
        p = resolve_safe_path("file.txt", base)
        assert p == (base / "file.txt").resolve()

    def test_absolute_path_inside_base(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        (base / "file.txt").touch()
        p = resolve_safe_path(str(base / "file.txt"), base)
        assert p == (base / "file.txt").resolve()

    def test_relative_path_default_cwd(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "data.txt").touch()
        p = resolve_safe_path("data.txt")
        assert p == (tmp_path / "data.txt").resolve()

    def test_traversal_raises(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        with pytest.raises(ValueError, match="Path traversal attempt blocked"):
            resolve_safe_path("../outside", base)

    def test_absolute_path_outside_base_raises(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        with pytest.raises(ValueError, match="Path traversal attempt blocked"):
            resolve_safe_path("/etc/passwd", base)


class TestSafeReadOpen:
    def test_reads_file_content(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        file = base / "test.txt"
        file.write_text("hello")
        with safe_read_open(file, base_dir=base) as f:
            assert f.read() == "hello"

    def test_raises_value_error_if_path_outside(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        with pytest.raises(ValueError, match="Path traversal attempt blocked"):
            safe_read_open("../outside", base_dir=base)

    def test_returns_file_like_object(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        file = base / "test.txt"
        file.write_text("data")
        f = safe_read_open(file, base_dir=base)
        assert hasattr(f, "read")
        f.close()

    def test_windows_fallback_when_ono_follow_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("devsecops_radar.core.path_security._O_NOFOLLOW", 0)
        base = tmp_path / "safe"
        base.mkdir()
        file = base / "test.txt"
        file.write_text("fallback")
        with safe_read_open(file, base_dir=base) as f:
            assert f.read() == "fallback"


class TestAtomicWrite:
    def test_writes_file_atomically(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        dest = base / "output.txt"
        with atomic_write(dest, base_dir=base) as f:
            f.write("content")
        assert dest.read_text() == "content"

    def test_cleans_up_on_exception(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        dest = base / "output.txt"
        with pytest.raises(ValueError):
            with atomic_write(dest, base_dir=base) as f:
                f.write("partial")
                raise ValueError("oops")
        # temp file should be gone
        assert len(list(base.glob(".sentinel_tmp_*"))) == 0

    def test_replaces_existing_file(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        dest = base / "output.txt"
        dest.write_text("old")
        with atomic_write(dest, base_dir=base) as f:
            f.write("new")
        assert dest.read_text() == "new"

    def test_writes_to_existing_subdirectory(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        sub = base / "sub"
        sub.mkdir()
        dest = sub / "out.txt"
        with atomic_write(dest, base_dir=base) as f:
            f.write("data")
        assert dest.read_text() == "data"

    def test_raises_if_dest_outside_base(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        outside = tmp_path / "outside.txt"
        with pytest.raises(ValueError, match="Path traversal attempt blocked"):
            with atomic_write(outside, base_dir=base):
                pass

    def test_writes_with_custom_encoding(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        dest = base / "out.txt"
        with atomic_write(dest, base_dir=base, encoding="utf-16") as f:
            f.write("unicode")
        assert dest.read_text(encoding="utf-16") == "unicode"

    def test_logs_debug_on_success(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        dest = base / "out.txt"
        with capture_loguru() as msgs:
            with atomic_write(dest, base_dir=base) as f:
                f.write("ok")
        assert any("Atomic write committed" in m for m in msgs)
