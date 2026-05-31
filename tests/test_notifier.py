from unittest.mock import AsyncMock, patch

import pytest

from devsecops_radar.core.notifier import notify_asana, notify_jira


@pytest.mark.asyncio
async def test_notify_jira_creates_issues():
    findings = [
        {"id": "CVE-1", "severity": "CRITICAL", "title": "Test", "target": "t", "description": "d"},
        {"id": "CVE-2", "severity": "HIGH", "title": "Test2", "target": "t2", "description": "d2"},
    ]
    with patch("devsecops_radar.core.notifier.httpx.AsyncClient") as mock_client_class:
        mock_instance = mock_client_class.return_value
        mock_instance.post = AsyncMock(
            return_value=AsyncMock(status_code=201, text="Created")
        )
        await notify_jira(findings, "https://jira.example.com", "token123")

        # Only the CRITICAL finding triggers a request
        assert mock_instance.post.call_count == 1
        call_args = mock_instance.post.call_args[1]
        assert call_args["headers"]["Authorization"] == "Bearer token123"
        assert "CVE-1" in call_args["json"]["fields"]["summary"]


@pytest.mark.asyncio
async def test_notify_jira_no_critical():
    findings = [{"id": "CVE-2", "severity": "HIGH", "title": "T", "target": "t", "description": "d"}]
    with patch("devsecops_radar.core.notifier.httpx.AsyncClient") as mock_client_class:
        await notify_jira(findings, "https://jira.example.com", "token123")
        mock_instance = mock_client_class.return_value
        # No call should have been made because no CRITICAL finding
        assert mock_instance.post.call_count == 0


@pytest.mark.asyncio
async def test_notify_jira_missing_config():
    with patch("devsecops_radar.core.notifier.httpx.AsyncClient") as mock_client_class:
        await notify_jira([], "", "")
        mock_instance = mock_client_class.return_value
        mock_instance.post.assert_not_called()


@pytest.mark.asyncio
async def test_notify_jira_request_failure_does_not_raise():
    findings = [{"id": "CVE-1", "severity": "CRITICAL", "title": "T", "target": "t", "description": "d"}]
    with patch("devsecops_radar.core.notifier.httpx.AsyncClient") as mock_client_class:
        mock_instance = mock_client_class.return_value
        mock_instance.post = AsyncMock(
            return_value=AsyncMock(status_code=400, text="Bad request")
        )
        await notify_jira(findings, "https://jira.example.com", "token123")
        # Request was still attempted, function didn't crash
        assert mock_instance.post.call_count == 1


@pytest.mark.asyncio
async def test_notify_asana_creates_tasks():
    findings = [{"id": "CVE-3", "severity": "CRITICAL", "title": "T", "target": "t", "description": "d"}]
    with patch("devsecops_radar.core.notifier.httpx.AsyncClient") as mock_client_class:
        mock_instance = mock_client_class.return_value
        mock_instance.post = AsyncMock(
            return_value=AsyncMock(status_code=201, text="Created")
        )
        await notify_asana(findings, "token_asana", "12345")
        assert mock_instance.post.call_count == 1
        call_args = mock_instance.post.call_args[1]
        assert call_args["headers"]["Authorization"] == "Bearer token_asana"
        assert "CVE-3" in call_args["json"]["data"]["name"]


@pytest.mark.asyncio
async def test_notify_asana_no_critical():
    findings = [{"id": "CVE-4", "severity": "LOW", "title": "T", "target": "t", "description": "d"}]
    with patch("devsecops_radar.core.notifier.httpx.AsyncClient") as mock_client_class:
        await notify_asana(findings, "token", "ws")
        mock_instance = mock_client_class.return_value
        assert mock_instance.post.call_count == 0


@pytest.mark.asyncio
async def test_notify_asana_missing_config():
    with patch("devsecops_radar.core.notifier.httpx.AsyncClient") as mock_client_class:
        await notify_asana([], "", "")
        mock_instance = mock_client_class.return_value
        mock_instance.post.assert_not_called()


@pytest.mark.asyncio
async def test_notify_asana_request_failure_does_not_raise():
    findings = [{"id": "CVE-1", "severity": "CRITICAL", "title": "T", "target": "t", "description": "d"}]
    with patch("devsecops_radar.core.notifier.httpx.AsyncClient") as mock_client_class:
        mock_instance = mock_client_class.return_value
        mock_instance.post = AsyncMock(
            return_value=AsyncMock(status_code=400, text="Bad request")
        )
        await notify_asana(findings, "token_asana", "ws_id")
        assert mock_instance.post.call_count == 1
