"""Tests for the PDF report generation and redaction utilities.

Covers basic PDF creation, path‑traversal prevention, and the
``redact_sensitive`` helper.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Skip entire module if reportlab is not installed (keeps CI green)
# ---------------------------------------------------------------------------
try:
    from reportlab.lib.pagesizes import A4  # noqa: F401
except ImportError:
    pytest.skip("reportlab is not installed – skipping PDF tests", allow_module_level=True)

from devsecops_radar.core.reporting import generate_pdf_report, redact_sensitive


class TestGeneratePdfReport:
    """Verify PDF creation and path validation."""

    SAMPLE_FINDINGS = [
        {
            "tool": "trivy",
            "id": "CVE-2024-0001",
            "severity": "HIGH",
            "target": "app/server.py",
            "title": "Remote Code Execution",
            "description": "A remote attacker may execute arbitrary code.",
        }
    ]
    SAMPLE_SUMMARY = {
        "executive_summary": "Test summary",
        "risk_score": 78.5,
    }

    def test_basic_pdf_creation(self, tmp_path: Path) -> None:
        """A valid report is created and is a well‑formed PDF."""
        out_file = str(tmp_path / "report.pdf")
        generate_pdf_report(
            self.SAMPLE_FINDINGS,
            self.SAMPLE_SUMMARY,
            output_file=out_file,
            base_dir=tmp_path,
        )
        assert Path(out_file).is_file()
        with open(out_file, "rb") as f:
            header = f.read(5)
        assert header == b"%PDF-"

    def test_path_validation_blocks_escape(self, tmp_path: Path) -> None:
        """An output path outside base_dir raises a ValueError."""
        out_file = str(tmp_path / "../outside.pdf")
        with pytest.raises(ValueError, match="Path traversal attempt blocked"):
            generate_pdf_report(
                self.SAMPLE_FINDINGS,
                self.SAMPLE_SUMMARY,
                output_file=out_file,
                base_dir=tmp_path,
            )


class TestRedactSensitive:
    """Ensure secret patterns are replaced with ``***REDACTED***``."""

    def test_strips_bearer_token(self) -> None:
        text = (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        cleaned = redact_sensitive(text)
        assert "***REDACTED***" in cleaned
        assert "eyJ" not in cleaned

    def test_strips_github_token(self) -> None:
        # 36 characters after ghp_ to match the regex
        text = "export GITHUB_TOKEN=ghp_" + "a" * 36
        cleaned = redact_sensitive(text)
        assert "***REDACTED***" in cleaned
        assert "ghp_" not in cleaned

    def test_non_sensitive_text_passes_through(self) -> None:
        text = "No secrets here, just a normal sentence."
        assert redact_sensitive(text) == text

    def test_multiple_patterns_in_one_line(self) -> None:
        # Two different patterns, each with correct lengths
        text = f"key1=ghp_{'a'*36}, key2=gho_{'b'*36}"
        cleaned = redact_sensitive(text)
        assert cleaned.count("***REDACTED***") >= 2
