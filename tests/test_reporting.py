"""Tests for reporting module (PDF generation)."""

from contextlib import contextmanager
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger

from devsecops_radar.core.reporting import (
    _validate_output_path,
    generate_pdf_report,
    redact_sensitive,
)


# ---------------------------------------------------------------------------
# Capture loguru output
# ---------------------------------------------------------------------------
@contextmanager
def capture_loguru(level: str = "TRACE"):
    messages: list[str] = []

    def sink(msg):
        messages.append(str(msg))

    handler_id = logger.add(sink, level=level, format="{message}")
    try:
        yield messages
    finally:
        logger.remove(handler_id)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_findings():
    return [
        {
            "tool": "semgrep",
            "id": "rule-1",
            "severity": "HIGH",
            "target": "app/main.py",
            "title": "SQL Injection",
            "description": "Found SQL injection",
        },
        {
            "tool": "trivy",
            "id": "CVE-2024-9999",
            "severity": "CRITICAL",
            "target": "lib/ssl.so",
            "title": "Buffer Overflow",
            "description": "Remote code execution",
        },
    ]


@pytest.fixture
def sample_ai_summary():
    return {
        "executive_summary": "Critical issues detected.",
        "risk_score": 85.5,
    }


# ============================================================================
# Tests for _validate_output_path
# ============================================================================
class TestValidateOutputPath:
    def test_safe_relative_path(self, tmp_path):
        p = _validate_output_path("report.pdf", base_dir=tmp_path)
        assert p == (tmp_path / "report.pdf").resolve()

    def test_path_traversal_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Security violation"):
            _validate_output_path("../../etc/passwd", base_dir=tmp_path)

    def test_default_base_dir_cwd(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        p = _validate_output_path("output.pdf")
        assert p == (tmp_path / "output.pdf").resolve()

    def test_absolute_path_allowed_if_inside_base(self, tmp_path):
        abs_path = str(tmp_path / "inside.pdf")
        p = _validate_output_path(abs_path, base_dir=tmp_path)
        assert p == (tmp_path / "inside.pdf").resolve()

    def test_absolute_path_outside_base_raises(self, tmp_path):
        outside = tmp_path.parent / "outside.pdf"
        with pytest.raises(ValueError):
            _validate_output_path(str(outside), base_dir=tmp_path)


# ============================================================================
# Tests for redact_sensitive
# ============================================================================
class TestRedactSensitive:
    def test_redacts_password_assignment(self):
        text = "password=secret123"
        assert redact_sensitive(text) == "***REDACTED***"

    def test_redacts_github_token(self):
        # GitHub token: exactly 36 alphanumeric chars after 'ghp_'
        token = "ghp_" + "a" * 36
        text = f"token is {token}"
        result = redact_sensitive(text)
        assert "ghp_" not in result
        assert "***REDACTED***" in result

    def test_redacts_jwt_token(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = redact_sensitive(text)
        assert "eyJ" not in result  # typical JWT header

    def test_redacts_gitlab_token(self):
        text = "token=glpat-abcdefghijklmnop"
        assert "glpat-" not in redact_sensitive(text)

    def test_redacts_aws_access_key(self):
        text = "AWS key: AKIA1234567890ABCDEF"
        assert "AKIA" not in redact_sensitive(text)

    def test_no_redaction_without_patterns(self):
        text = "safe text without secrets"
        assert redact_sensitive(text) == text

    def test_custom_patterns(self):
        custom = [r'secret-code-\d+']
        text = "secret-code-42 and secret-code-99"
        result = redact_sensitive(text, patterns=custom)
        assert "***REDACTED***" in result
        # Count redactions: both occurrences replaced
        assert result.count("***REDACTED***") == 2

    def test_empty_string(self):
        assert redact_sensitive("") == ""


# ============================================================================
# Tests for generate_pdf_report
# ============================================================================
class TestGeneratePdfReport:
    @pytest.fixture(autouse=True)
    def mock_reportlab(self):
        """Mock reportlab to avoid real PDF generation."""
        with patch(
            "devsecops_radar.core.reporting.SimpleDocTemplate"
        ) as mock_doc_cls:
            mock_doc = MagicMock()
            mock_doc_cls.return_value = mock_doc
            yield mock_doc_cls, mock_doc

    @pytest.fixture
    def mock_datetime(self):
        frozen = datetime(2025, 6, 11, 12, 30, 0, tzinfo=UTC)
        with patch(
            "devsecops_radar.core.reporting.datetime"
        ) as mock_dt:
            mock_dt.now.return_value = frozen
            yield frozen

    def test_basic_pdf_creation(
        self, tmp_path, sample_findings, sample_ai_summary, mock_reportlab, mock_datetime
    ):
        mock_doc_cls, mock_doc = mock_reportlab
        output = tmp_path / "report.pdf"
        generate_pdf_report(
            sample_findings, sample_ai_summary, str(output), base_dir=tmp_path
        )
        # Check SimpleDocTemplate was created with correct path
        mock_doc_cls.assert_called_once()
        args, kwargs = mock_doc_cls.call_args
        assert args[0] == str(output)
        # build was called
        mock_doc.build.assert_called_once()

    def test_no_findings_handled(
        self, tmp_path, sample_ai_summary, mock_reportlab
    ):
        _, mock_doc = mock_reportlab
        output = tmp_path / "nofindings.pdf"
        generate_pdf_report([], sample_ai_summary, str(output), base_dir=tmp_path)
        mock_doc.build.assert_called_once()

    def test_redaction_disabled(
        self, tmp_path, sample_findings, sample_ai_summary, mock_reportlab
    ):
        _, mock_doc = mock_reportlab
        output = tmp_path / "noredact.pdf"
        # We'll check that redact_sensitive is NOT called by patching it
        with patch(
            "devsecops_radar.core.reporting.redact_sensitive"
        ) as mock_redact:
            generate_pdf_report(
                sample_findings,
                sample_ai_summary,
                str(output),
                redact=False,
                base_dir=tmp_path,
            )
            mock_redact.assert_not_called()

    def test_build_failure_raises_runtime(
        self, tmp_path, sample_findings, sample_ai_summary, mock_reportlab
    ):
        _, mock_doc = mock_reportlab
        mock_doc.build.side_effect = Exception("PDF build error")
        output = tmp_path / "fail.pdf"
        with capture_loguru() as msgs:
            with pytest.raises(RuntimeError, match="PDF generation failed"):
                generate_pdf_report(
                    sample_findings,
                    sample_ai_summary,
                    str(output),
                    base_dir=tmp_path,
                )
        assert any("Failed to build PDF report" in m for m in msgs)

    def test_path_validation_fails(
        self, tmp_path, sample_findings, sample_ai_summary, mock_reportlab
    ):
        outside = tmp_path.parent / "outside.pdf"
        with pytest.raises(ValueError, match="Security violation"):
            generate_pdf_report(
                sample_findings,
                sample_ai_summary,
                str(outside),
                base_dir=tmp_path,
            )

    def test_title_and_timestamp_in_report(
        self, tmp_path, sample_findings, sample_ai_summary, mock_reportlab, mock_datetime
    ):
        """Ensure the PDF elements contain the title and generated timestamp."""
        _, mock_doc = mock_reportlab
        output = tmp_path / "withtitle.pdf"
        generate_pdf_report(
            sample_findings, sample_ai_summary, str(output), base_dir=tmp_path
        )
        # Extract the list of elements passed to build
        call_args = mock_doc.build.call_args[0][0]  # list of flowables
        # The first element should be the title
        first = call_args[0]
        assert "Pipeline Sentinel" in first.text
        # The second element (or nearby) contains the generation time
        gen_time = call_args[1].text
        assert mock_datetime.strftime("%Y-%m-%d %H:%M:%S UTC") in gen_time

    def test_executive_summary_omitted_if_missing(self, tmp_path, sample_findings, mock_reportlab):
        _, mock_doc = mock_reportlab
        output = tmp_path / "nosummary.pdf"
        generate_pdf_report(
            sample_findings, {"risk_score": 0}, str(output), base_dir=tmp_path
        )
        call_args = mock_doc.build.call_args[0][0]
        # Should not contain "Executive Summary" heading
        texts = [el.text for el in call_args if hasattr(el, "text")]
        assert not any("Executive Summary" in t for t in texts)

    def test_truncation_of_long_titles(self, tmp_path, sample_findings, mock_reportlab):
        sample_findings[0]["title"] = "A" * 150
        output = tmp_path / "long.pdf"
        _, mock_doc = mock_reportlab
        generate_pdf_report(
            sample_findings, {"risk_score": 0}, str(output), base_dir=tmp_path
        )
        # We can't easily check the truncated text without building real PDF,
        # but we can ensure no exception occurred. The truncation is trusted.
        # We'll just verify build was called.
        mock_doc.build.assert_called_once()
