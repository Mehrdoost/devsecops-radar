from unittest.mock import AsyncMock, patch

import pytest

from devsecops_radar.core.notifier import notify_asana, notify_jira


@pytest.fixture
def critical_findings():
    return [
        {
            "id": "CVE-2026-001",
            "severity": "CRITICAL",
            "title": "Critical RCE",
            "target": "web-server",
            "description": "Remote code execution in nginx"
        },
        {
            "id": "CVE-2026-002",
            "severity": "HIGH",
            "title": "High XSS",
            "target": "app-server",
            "description": "Cross-site scripting"
        }
    ]


# -------------------------------------------------------------------
# notify_jira tests
# -------------------------------------------------------------------
class TestNotifyJira:
    @pytest.mark.asyncio
    async def test_missing_url_or_token(self, critical_findings, caplog):
        """Should log a warning and return without making any request."""
        await notify_jira(critical_findings, "", "")
        assert "Jira URL or API token not configured" in caplog.text

        await notify_jira(critical_findings, "https://jira.example.com", "")
        assert "Jira URL or API token not configured" in caplog.text

        await notify_jira(critical_findings, "", "token123")
        assert "Jira URL or API token not configured" in caplog.text

    @pytest.mark.asyncio
    async def test_creates_issue_for_critical_only(self, critical_findings):
        """Only CRITICAL findings should create Jira issues."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=AsyncMock(status_code=201))

        with patch("httpx.AsyncClient", return_value=mock_client):
            await notify_jira(critical_findings, "https://jira.example.com", "token123")

        # Only one call for the CRITICAL finding, not for HIGH
        assert mock_client.post.call_count == 1
        args = mock_client.post.call_args[0]
        assert args[0] == "https://jira.example.com/rest/api/2/issue"
        payload = mock_client.post.call_args[1]["json"]
        assert "CVE-2026-001" in payload["fields"]["summary"]

    @pytest.mark.asyncio
    async def test_jira_request_failure(self, critical_findings, caplog):
        """Non-201 response should log a warning."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=AsyncMock(status_code=400, text="Bad request"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            await notify_jira(critical_findings, "https://jira.example.com", "token123")

        assert "Failed to create Jira issue" in caplog.text

    @pytest.mark.asyncio
    async def test_jira_exception_handling(self, critical_findings, caplog):
        """Exception during request should be logged but not raised."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("Network error"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            await notify_jira(critical_findings, "https://jira.example.com", "token123")

        assert "Jira notification failed" in caplog.text


# -------------------------------------------------------------------
# notify_asana tests
# -------------------------------------------------------------------
class TestNotifyAsana:
    @pytest.mark.asyncio
    async def test_missing_token_or_workspace(self, critical_findings, caplog):
        """Should log a warning and return without making any request."""
        await notify_asana(critical_findings, "", "")
        assert "Asana token or workspace not configured" in caplog.text

        await notify_asana(critical_findings, "token123", "")
        assert "Asana token or workspace not configured" in caplog.text

        await notify_asana(critical_findings, "", "workspace123")
        assert "Asana token or workspace not configured" in caplog.text

    @pytest.mark.asyncio
    async def test_creates_task_for_critical_only(self, critical_findings):
        """Only CRITICAL findings should create Asana tasks."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=AsyncMock(status_code=201))

        with patch("httpx.AsyncClient", return_value=mock_client):
            await notify_asana(critical_findings, "token123", "workspace123")

        assert mock_client.post.call_count == 1
        args = mock_client.post.call_args[0]
        assert args[0] == "https://app.asana.com/api/1.0/tasks"
        payload = mock_client.post.call_args[1]["json"]
        assert "CVE-2026-001" in payload["data"]["name"]

    @pytest.mark.asyncio
    async def test_asana_request_failure(self, critical_findings, caplog):
        """Non-201 response should log a warning."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=AsyncMock(status_code=400, text="Bad request"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            await notify_asana(critical_findings, "token123", "workspace123")

        assert "Failed to create Asana task" in caplog.text

    @pytest.mark.asyncio
    async def test_asana_exception_handling(self, critical_findings, caplog):
        """Exception during request should be logged but not raised."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("Network error"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            await notify_asana(critical_findings, "token123", "workspace123")

        assert "Asana notification failed" in caplog.text
