"""Tests for notification module (Jira and Asana integration)."""

from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from loguru import logger

from devsecops_radar.core.notifier import (
    _create_asana_task,
    _create_jira_issue,
    _truncate,
    _validate_jira_url,
    notify_asana,
    notify_jira,
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
# Mock httpx.AsyncClient to avoid h2 incompatibility
# ---------------------------------------------------------------------------
class MockAsyncClient:
    """A mock that can be used as an async context manager."""
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def post(self, *args, **kwargs):
        return MagicMock(status_code=201, text="")


@pytest.fixture
def patch_httpx_client():
    """Replace httpx.AsyncClient with our safe mock."""
    with patch("httpx.AsyncClient", new=MockAsyncClient):
        yield


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def make_finding(severity="CRITICAL", **kwargs):
    base = {
        "id": "CVE-2024-0001",
        "title": "Test vulnerability",
        "severity": severity,
        "target": "app.py",
        "description": "A test finding",
    }
    base.update(kwargs)
    return base


# ============================================================================
# Tests for _validate_jira_url
# ============================================================================
class TestValidateJiraUrl:
    def test_valid_url_with_path(self):
        url = "https://mycompany.atlassian.net/jira"
        assert _validate_jira_url(url) == url

    def test_valid_url_without_path(self):
        url = "https://mycompany.atlassian.net"
        assert _validate_jira_url(url) == url

    def test_missing_https(self):
        with capture_loguru() as msgs:
            assert _validate_jira_url("http://mycompany.atlassian.net") is None
        assert any("must use HTTPS" in m for m in msgs)

    def test_no_hostname(self):
        assert _validate_jira_url("https://") is None

    def test_invalid_characters(self):
        # Use a URL that contains a space – this triggers the new validation
        with capture_loguru() as msgs:
            assert _validate_jira_url("https://evil.com/issue query=1") is None
        assert any("invalid characters" in m for m in msgs)

    def test_empty_url(self):
        assert _validate_jira_url("") is None

    def test_strips_trailing_slash(self):
        url = "https://mycompany.atlassian.net/"
        result = _validate_jira_url(url)
        assert result == "https://mycompany.atlassian.net"

# ============================================================================
# Tests for _truncate
# ============================================================================
class TestTruncate:
    def test_short_text(self):
        assert _truncate("hello") == "hello"

    def test_long_text(self):
        long_text = "a" * 1500
        result = _truncate(long_text, 1000)
        assert len(result) == 1000 + len("... [TRUNCATED]")  # 1015
        assert result.endswith("... [TRUNCATED]")

    def test_none(self):
        assert _truncate(None) is None

    def test_empty_string(self):
        assert _truncate("") == ""


# ============================================================================
# Tests for _create_jira_issue
# ============================================================================
class TestCreateJiraIssue:
    @pytest.mark.asyncio
    async def test_success(self):
        finding = make_finding()
        mock_client = AsyncMock()
        mock_response = MagicMock(status_code=201, text="")
        mock_client.post.return_value = mock_response

        with capture_loguru() as msgs:
            await _create_jira_issue(
                mock_client,
                "https://jira.example.com",
                finding,
                "fake-token",
                "SEC",
                "Bug",
            )
        mock_client.post.assert_called_once()
        args, kwargs = mock_client.post.call_args
        assert args[0] == "https://jira.example.com/rest/api/2/issue"
        payload = kwargs["json"]
        assert payload["fields"]["project"]["key"] == "SEC"
        assert payload["fields"]["issuetype"]["name"] == "Bug"
        assert payload["fields"]["summary"].startswith("[Pipeline Sentinel]")
        assert any("Created Jira issue" in m for m in msgs)

    @pytest.mark.asyncio
    async def test_failure(self):
        finding = make_finding()
        mock_client = AsyncMock()
        mock_response = MagicMock(status_code=400, text="Bad Request")
        mock_client.post.return_value = mock_response

        with capture_loguru() as msgs:
            await _create_jira_issue(
                mock_client,
                "https://jira.example.com",
                finding,
                "fake-token",
                "SEC",
                "Bug",
            )
        assert any("Failed to create Jira issue" in m for m in msgs)

    @pytest.mark.asyncio
    async def test_truncation_of_summary(self):
        # Title length causes summary to exceed 255 chars before truncation,
        # so _truncate will cut it to 255 and then append "... [TRUNCATED]".
        # Final length = 255 + len("... [TRUNCATED]") = 270.
        finding = make_finding(
            title="Very long title " + "x" * 300, id="CVE-12345"
        )
        mock_client = AsyncMock()
        mock_response = MagicMock(status_code=201, text="")
        mock_client.post.return_value = mock_response

        await _create_jira_issue(
            mock_client,
            "https://jira.example.com",
            finding,
            "token",
            "KEY",
            "Task",
        )
        payload = mock_client.post.call_args[1]["json"]
        summary = payload["fields"]["summary"]
        assert summary.startswith("[Pipeline Sentinel] CVE-12345:")
        assert summary.endswith("... [TRUNCATED]")
        # The total length is 255 chars of payload + 15 char suffix
        assert len(summary) == 255 + len("... [TRUNCATED]")


# ============================================================================
# Tests for _create_asana_task
# ============================================================================
class TestCreateAsanaTask:
    @pytest.mark.asyncio
    async def test_success(self):
        finding = make_finding()
        mock_client = AsyncMock()
        mock_response = MagicMock(status_code=201, text="")
        mock_client.post.return_value = mock_response

        with capture_loguru() as msgs:
            await _create_asana_task(
                mock_client, finding, "token", "12345"
            )
        mock_client.post.assert_called_once()
        args, kwargs = mock_client.post.call_args
        assert args[0] == "https://app.asana.com/api/1.0/tasks"
        assert kwargs["json"]["data"]["workspace"] == "12345"
        assert any("Created Asana task" in m for m in msgs)

    @pytest.mark.asyncio
    async def test_failure(self):
        finding = make_finding()
        mock_client = AsyncMock()
        mock_response = MagicMock(status_code=500, text="Server Error")
        mock_client.post.return_value = mock_response

        with capture_loguru() as msgs:
            await _create_asana_task(
                mock_client, finding, "token", "12345"
            )
        assert any("Failed to create Asana task" in m for m in msgs)


# ============================================================================
# Tests for notify_jira
# ============================================================================
class TestNotifyJira:
    @pytest.fixture(autouse=True)
    def setup_env(self, monkeypatch):
        monkeypatch.setenv("JIRA_PROJECT_KEY", "TEST")
        monkeypatch.setenv("JIRA_ISSUE_TYPE", "Vulnerability")

    @pytest.mark.asyncio
    async def test_sends_only_critical(self, patch_httpx_client):
        findings = [
            make_finding("CRITICAL", id="CVE-1"),
            make_finding("HIGH", id="CVE-2"),
            make_finding("CRITICAL", id="CVE-3"),
        ]
        with patch(
            "devsecops_radar.core.notifier._create_jira_issue",
            new_callable=AsyncMock,
        ) as mock_create:
            await notify_jira(
                findings, "https://jira.example.com", "token"
            )
            # Called twice for the two CRITICAL findings
            assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_skips_on_invalid_url(self, patch_httpx_client):
        with capture_loguru() as msgs:
            await notify_jira([make_finding()], "http://bad.url", "token")
        assert any("Jira URL invalid" in m for m in msgs)

    @pytest.mark.asyncio
    async def test_skips_on_missing_token(self, patch_httpx_client):
        with capture_loguru() as msgs:
            await notify_jira(
                [make_finding()], "https://jira.example.com", ""
            )
        assert any("Jira API token not configured" in m for m in msgs)

    @pytest.mark.asyncio
    async def test_handles_exception_in_create(self, patch_httpx_client):
        finding = make_finding()
        with patch(
            "devsecops_radar.core.notifier._create_jira_issue",
            side_effect=Exception("network error"),
        ), capture_loguru() as msgs:
            await notify_jira(
                [finding], "https://jira.example.com", "token"
            )
        assert any("ultimately failed" in m for m in msgs)


# ============================================================================
# Tests for notify_asana
# ============================================================================
class TestNotifyAsana:
    @pytest.mark.asyncio
    async def test_sends_only_critical(self, patch_httpx_client):
        findings = [
            make_finding("CRITICAL", id="CVE-1"),
            make_finding("MEDIUM", id="CVE-2"),
        ]
        with patch(
            "devsecops_radar.core.notifier._create_asana_task",
            new_callable=AsyncMock,
        ) as mock_create:
            await notify_asana(findings, "token", "12345")
            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_skips_on_missing_token(self, patch_httpx_client):
        with capture_loguru() as msgs:
            await notify_asana([make_finding()], "", "12345")
        assert any("token or workspace GID not configured" in m for m in msgs)

    @pytest.mark.asyncio
    async def test_skips_on_invalid_workspace_gid(self, patch_httpx_client):
        with capture_loguru() as msgs:
            await notify_asana([make_finding()], "token", "abc")
        assert any("Invalid Asana workspace GID format" in m for m in msgs)

    @pytest.mark.asyncio
    async def test_handles_exception_in_create(self, patch_httpx_client):
        finding = make_finding()
        with patch(
            "devsecops_radar.core.notifier._create_asana_task",
            side_effect=Exception("timeout"),
        ), capture_loguru() as msgs:
            await notify_asana([finding], "token", "12345")
        assert any("ultimately failed" in m for m in msgs)
