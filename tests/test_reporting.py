from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from devsecops_radar.core.reporting import (
    _validate_output_path,
    generate_pdf_report,
    redact_sensitive,
)


# ---------------------------------------------------------------------------
# _validate_output_path
# ---------------------------------------------------------------------------
class TestValidateOutputPath:
    def test_valid_path_inside_base(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        out = base / "report.pdf"
        out.touch()
        path = _validate_output_path("report.pdf", base_dir=base)
        assert path == out

    def test_default_base_is_cwd(self, tmp_path):
        cwd = tmp_path
        out = cwd / "out.pdf"
        out.touch()
        with patch("devsecops_radar.core.reporting.Path.cwd", return_value=cwd):
            path = _validate_output_path("out.pdf")
            assert path == out

    def test_path_traversal_raises(self, tmp_path):
        base = tmp_path / "safe"
        base.mkdir()
        with pytest.raises(ValueError, match="Security violation"):
            _validate_output_path("../etc/passwd", base_dir=base)

    def test_custom_base_resolved(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        out = base / "x.pdf"
        out.touch()
        path = _validate_output_path("x.pdf", base_dir=base)
        assert path == out


# ---------------------------------------------------------------------------
# redact_sensitive
# ---------------------------------------------------------------------------
class TestRedactSensitive:
    def test_default_patterns_redact_secrets(self):
        text = "password = supersecret123\nSECRET: abc\n"
        redacted = redact_sensitive(text)
        assert "supersecret123" not in redacted
        assert "***REDACTED***" in redacted

    def test_github_token_redacted(self):
        text = "export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        redacted = redact_sensitive(text)
        assert "ghp_" not in redacted
        assert "***REDACTED***" in redacted

    def test_jwt_token_redacted(self):
        jwt_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        text = f"Authorization: Bearer {jwt_token}"
        redacted = redact_sensitive(text)
        assert jwt_token not in redacted
        assert "***REDACTED***" in redacted

    def test_custom_patterns(self):
        text = "db_password=admin123"
        custom_pat = [r'db_password=\S+']
        redacted = redact_sensitive(text, patterns=custom_pat)
        assert "admin123" not in redacted
        assert "***REDACTED***" in redacted

    def test_no_patterns_matches(self):
        text = "clean text"
        redacted = redact_sensitive(text)
        assert redacted == "clean text"

    def test_multiple_matches(self):
        text = "password=pass1 password=pass2"
        redacted = redact_sensitive(text)
        assert redacted.count("***REDACTED***") == 2

    def test_empty_text(self):
        assert redact_sensitive("") == ""


# ---------------------------------------------------------------------------
# generate_pdf_report
# ---------------------------------------------------------------------------
class TestGeneratePdfReport:
    @pytest.fixture
    def mock_dependencies(self):
        with patch(
            "devsecops_radar.core.reporting.SimpleDocTemplate"
        ) as mock_doc_class, \
             patch("devsecops_radar.core.reporting.logger") as mock_logger, \
             patch(
                 "devsecops_radar.core.reporting.datetime"
             ) as mock_datetime:

            fixed_dt = datetime(2025, 6, 7, 12, 0, 0, tzinfo=UTC)
            mock_datetime.now.return_value = fixed_dt
            mock_doc_instance = MagicMock()
            mock_doc_class.return_value = mock_doc_instance

            yield {
                "mock_doc_class": mock_doc_class,
                "mock_logger": mock_logger,
                "mock_datetime": mock_datetime,
                "fixed_dt": fixed_dt,
                "mock_doc_instance": mock_doc_instance,
            }

    def test_path_validation_fails_raises(self):
        with patch(
            "devsecops_radar.core.reporting._validate_output_path"
        ) as mock_validate:
            mock_validate.side_effect = ValueError("traversal")
            with pytest.raises(ValueError, match="traversal"):
                generate_pdf_report([], {}, "bad.pdf")

    def test_generate_with_all_features(self, mock_dependencies):
        findings = [
            {
                "tool": "Semgrep", "id": "R1", "severity": "HIGH",
                "target": "app.py", "title": "SQLi",
            },
            {
                "tool": "Trivy", "id": "CVE-2025", "severity": "CRITICAL",
                "target": "image:latest", "title": "CVE",
            },
        ]
        ai_summary = {"executive_summary": "All clear", "risk_score": 85}
        with patch(
            "devsecops_radar.core.reporting._validate_output_path"
        ) as mock_validate, \
             patch(
                 "devsecops_radar.core.reporting.redact_sensitive"
             ) as mock_redact:

            mock_validate.return_value = Path("/safe/report.pdf")
            mock_redact.side_effect = lambda x, **kw: x

            generate_pdf_report(
                findings, ai_summary, "report.pdf", redact=True,
                base_dir="/safe"
            )

            mock_dependencies["mock_doc_instance"].build.assert_called_once()
            assert mock_redact.call_count >= 3
            mock_dependencies["mock_logger"].success.assert_called_once()
            args, _ = mock_dependencies["mock_logger"].success.call_args
            assert "report.pdf" in args[0]

    def test_no_findings(self, mock_dependencies):
        with patch(
            "devsecops_radar.core.reporting._validate_output_path",
            return_value=Path("out.pdf"),
        ), patch(
            "devsecops_radar.core.reporting.redact_sensitive",
            side_effect=lambda x: x,
        ):
            generate_pdf_report(
                [], {"executive_summary": "Empty"}, "report.pdf"
            )
            mock_dependencies["mock_doc_instance"].build.assert_called_once()

    def test_redact_disabled(self, mock_dependencies):
        findings = [
            {
                "tool": "Test", "id": "1", "severity": "LOW",
                "target": "secret=123", "title": "password=abc",
            }
        ]
        ai_summary = {"executive_summary": "secret=123"}
        with patch(
            "devsecops_radar.core.reporting._validate_output_path",
            return_value=Path("out.pdf"),
        ), patch(
            "devsecops_radar.core.reporting.redact_sensitive"
        ) as mock_redact:
            generate_pdf_report(
                findings, ai_summary, "report.pdf", redact=False
            )
            mock_redact.assert_not_called()

    def test_table_only_first_50_findings(self, mock_dependencies):
        findings = [
            {
                "tool": "T", "id": f"ID-{i}", "severity": "LOW",
                "target": "t", "title": "t",
            }
            for i in range(60)
        ]
        with patch(
            "devsecops_radar.core.reporting._validate_output_path",
            return_value=Path("out.pdf"),
        ), patch(
            "devsecops_radar.core.reporting.redact_sensitive",
            side_effect=lambda x: x,
        ):
            generate_pdf_report(findings, {}, "report.pdf")
            mock_dependencies["mock_doc_instance"].build.assert_called_once()

    def test_missing_summary_fields(self, mock_dependencies):
        ai_summary = {}
        with patch(
            "devsecops_radar.core.reporting._validate_output_path",
            return_value=Path("out.pdf"),
        ), patch(
            "devsecops_radar.core.reporting.redact_sensitive",
            side_effect=lambda x: x,
        ):
            generate_pdf_report([{"id": "1"}], ai_summary, "report.pdf")
            mock_dependencies["mock_doc_instance"].build.assert_called_once()

    def test_risk_score_zero_not_displayed(self, mock_dependencies):
        ai_summary = {"executive_summary": "low risk", "risk_score": 0}
        with patch(
            "devsecops_radar.core.reporting._validate_output_path",
            return_value=Path("out.pdf"),
        ), patch(
            "devsecops_radar.core.reporting.redact_sensitive",
            side_effect=lambda x: x,
        ):
            generate_pdf_report([], ai_summary, "report.pdf")
            mock_dependencies["mock_doc_instance"].build.assert_called_once()
