"""Tests for the minimal scanner plugin interface."""

import pytest

from devsecops_radar.plugins import ScannerPlugin


# ---------------------------------------------------------------------------
# Concrete implementation for testing
# ---------------------------------------------------------------------------
class _DummyPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "dummy"

    @property
    def version(self) -> str:
        return "0.1.0"

    def parse(self, file_path: str) -> list[dict]:
        return [{"tool": self.name, "id": "R1", "severity": "LOW", "target": file_path, "title": "Test"}]


# ============================================================================
# Tests
# ============================================================================
class TestScannerPlugin:
    def test_name_property(self):
        plugin = _DummyPlugin()
        assert plugin.name == "dummy"

    def test_version_property(self):
        plugin = _DummyPlugin()
        assert plugin.version == "0.1.0"

    def test_parse_returns_list_of_dicts(self):
        plugin = _DummyPlugin()
        results = plugin.parse("/tmp/report.json")
        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0]["id"] == "R1"

    def test_default_run_raises_not_implemented(self):
        plugin = _DummyPlugin()
        with pytest.raises(NotImplementedError, match="Direct run not supported"):
            plugin.run("some-target")

    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            ScannerPlugin()  # abstract class cannot be instantiated directly
