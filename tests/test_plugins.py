"""Unit tests for the base ScannerPlugin interface."""

from __future__ import annotations

from typing import Any

from devsecops_radar.plugins import ScannerPlugin


class MinimalPlugin(ScannerPlugin):
    """A concrete plugin implementing only the mandatory parse method."""

    @property
    def name(self) -> str:
        return "minimal"

    @property
    def version(self) -> str:
        return "0.1.0"

    def parse(self, file_path: str) -> list[dict[str, Any]]:
        _ = file_path
        return [{"id": "TEST-1", "title": "Sample"}]


class TestScannerPlugin:
    """Test the default behaviour of ScannerPlugin."""

    def test_default_run_returns_none(self) -> None:
        """A plugin that does not override run should return None."""
        plugin = MinimalPlugin()
        result = plugin.run("some-target")
        assert result is None

    def test_parse_returns_expected_findings(self, tmp_path: Any) -> None:
        """Ensure that a minimal parse implementation works correctly."""
        plugin = MinimalPlugin(allowed_base_dir=tmp_path)
        report = tmp_path / "report.json"
        report.write_text('{"findings":[]}')
        findings = plugin.parse(str(report))
        assert isinstance(findings, list)
        assert len(findings) == 1
        assert findings[0]["id"] == "TEST-1"
