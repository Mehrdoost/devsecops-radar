from unittest.mock import MagicMock, patch

from devsecops_radar.core.reporting import generate_pdf_report, redact_sensitive


def test_redact_sensitive_password():
    text = "password=secret123"
    result = redact_sensitive(text)
    assert "***REDACTED***" in result
    assert "secret123" not in result


def test_redact_sensitive_github_token():
    text = "ghp_1234567890abcdef1234567890abcdef12345678"
    result = redact_sensitive(text)
    assert "***REDACTED***" in result


def test_redact_sensitive_jwt():
    text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN"
    result = redact_sensitive(text)
    assert "***REDACTED***" in result


def test_redact_sensitive_custom_patterns():
    text = "api_key=12345"
    result = redact_sensitive(text, patterns=[r"api_key=\S+"])
    assert "***REDACTED***" in result


def test_redact_sensitive_none_patterns():
    text = "normal text"
    result = redact_sensitive(text)
    assert text == result


@patch('devsecops_radar.core.reporting.SimpleDocTemplate')
@patch('devsecops_radar.core.reporting.Paragraph')
@patch('devsecops_radar.core.reporting.Table')
@patch('devsecops_radar.core.reporting.TableStyle')
@patch('devsecops_radar.core.reporting.Spacer')
@patch('devsecops_radar.core.reporting.getSampleStyleSheet')
@patch('devsecops_radar.core.reporting.ParagraphStyle')
@patch('devsecops_radar.core.reporting.colors')
def test_generate_pdf_report_with_findings(
    mock_colors,
    mock_paragraphstyle,
    mock_getsamplestylesheet,
    mock_spacer,
    mock_tablestyle,
    mock_table,
    mock_paragraph,
    mock_simpledoctemplate,
):
    findings = [
        {"tool": "Trivy", "id": "CVE-1", "severity": "HIGH",
         "target": "test.txt", "title": "Test vuln",
         "description": "Test description"}
    ]
    ai_summary = {"executive_summary": "Test summary", "risk_score": 75}

    mock_doc_instance = MagicMock()
    mock_simpledoctemplate.return_value = mock_doc_instance

    generate_pdf_report(findings, ai_summary, "test.pdf")

    assert mock_simpledoctemplate.called
    assert mock_doc_instance.build.called


@patch('devsecops_radar.core.reporting.SimpleDocTemplate')
@patch('devsecops_radar.core.reporting.Paragraph')
@patch('devsecops_radar.core.reporting.getSampleStyleSheet')
def test_generate_pdf_report_no_findings(
    mock_styles,
    mock_paragraph,
    mock_simpledoctemplate,
):
    findings = []
    ai_summary = {"executive_summary": "No issues"}

    mock_doc_instance = MagicMock()
    mock_simpledoctemplate.return_value = mock_doc_instance

    generate_pdf_report(findings, ai_summary, "test.pdf")
    assert mock_simpledoctemplate.called


@patch('devsecops_radar.core.reporting.SimpleDocTemplate')
@patch('devsecops_radar.core.reporting.Paragraph')
@patch('devsecops_radar.core.reporting.getSampleStyleSheet')
def test_generate_pdf_report_redact_disabled(
    mock_styles,
    mock_paragraph,
    mock_simpledoctemplate,
):
    findings = [
        {"tool": "Trivy", "id": "CVE-1", "severity": "LOW",
         "target": "test.txt", "title": "secret=abc", "description": ""}
    ]
    ai_summary = {"executive_summary": "Summary with secret=abc"}

    mock_doc_instance = MagicMock()
    mock_simpledoctemplate.return_value = mock_doc_instance

    generate_pdf_report(findings, ai_summary, "test.pdf", redact=False)
    assert mock_simpledoctemplate.called
