"""Tests for reporting module (PDF generation) – fully updated."""

from contextlib import contextmanager
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger

from devsecops_radar.core.reporting import (
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
# Tests for redact_sensitive (unchanged)
# ============================================================================
class TestRedactSensitive:
    def test_redacts_password_assignment(self):
        text = "password=secret123"
        assert redact_sensitive(text) == "***REDACTED***"

    def test_redacts_github_token(self):
        token = "ghp_" + "a" * 36
        text = f"token is {token}"
        result = redact_sensitive(text)
        assert "ghp_" not in result
        assert "***REDACTED***" in result

    def test_redacts_jwt_token(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = redact_sensitive(text)
        assert "eyJ" not in result

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
        mock_doc_cls.assert_called_once()
        args, kwargs = mock_doc_cls.call_args
        assert args[0] == str(output)
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

    def test_build_failure_raises_exception(
        self, tmp_path, sample_findings, sample_ai_summary, mock_reportlab
    ):
        """The PDF build error now propagates directly without wrapping."""
        _, mock_doc = mock_reportlab
        mock_doc.build.side_effect = Exception("PDF build error")
        output = tmp_path / "fail.pdf"
        with pytest.raises(Exception, match="PDF build error"):
            generate_pdf_report(
                sample_findings,
                sample_ai_summary,
                str(output),
                base_dir=tmp_path,
            )

    def test_path_validation_fails(
        self, tmp_path, sample_findings, sample_ai_summary, mock_reportlab
    ):
        outside = tmp_path.parent / "outside.pdf"
        with pytest.raises(ValueError, match="outside"):
            generate_pdf_report(
                sample_findings,
                sample_ai_summary,
                str(outside),
                base_dir=tmp_path,
            )

    def test_title_and_timestamp_in_report(
        self, tmp_path, sample_findings, sample_ai_summary, mock_reportlab, mock_datetime
    ):
        _, mock_doc = mock_reportlab
        output = tmp_path / "withtitle.pdf"
        generate_pdf_report(
            sample_findings, sample_ai_summary, str(output), base_dir=tmp_path
        )
        call_args = mock_doc.build.call_args[0][0]
        first = call_args[0]
        assert "Pipeline Sentinel" in first.text
        gen_time = call_args[1].text
        assert mock_datetime.strftime("%Y-%m-%d %H:%M:%S UTC") in gen_time

    def test_executive_summary_omitted_if_missing(self, tmp_path, sample_findings, mock_reportlab):
        _, mock_doc = mock_reportlab
        output = tmp_path / "nosummary.pdf"
        generate_pdf_report(
            sample_findings, {"risk_score": 0}, str(output), base_dir=tmp_path
        )
        call_args = mock_doc.build.call_args[0][0]
        texts = [el.text for el in call_args if hasattr(el, "text")]
        assert not any("Executive Summary" in t for t in texts)

    def test_truncation_of_long_titles(self, tmp_path, sample_findings, mock_reportlab):
        sample_findings[0]["title"] = "A" * 150
        output = tmp_path / "long.pdf"
        _, mock_doc = mock_reportlab
        generate_pdf_report(
            sample_findings, {"risk_score": 0}, str(output), base_dir=tmp_path
        )
        mock_doc.build.assert_called_once()
