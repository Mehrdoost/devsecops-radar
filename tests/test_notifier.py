from unittest.mock import AsyncMock, patch

import pytest

from devsecops_radar.core.notifier import notify_asana, notify_jira


@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_notify_jira_missing_config(mock_async_client_cls):
    """Should not make any request when URL or token is missing."""
    await notify_jira([], "", "")
    # AsyncClient constructor was never called because function returned early
    mock_async_client_cls.assert_not_called()

    await notify_jira([], "https://jira.example.com", "")
    mock_async_client_cls.assert_not_called()

    await notify_jira([], "", "token")
    mock_async_client_cls.assert_not_called()


@pytest.mark.asyncio
async def test_notify_jira_critical_only():
    """Only CRITICAL findings trigger a Jira request."""
    findings = [
        {"id": "CVE-1", "severity": "CRITICAL", "title": "Test", "target": "t", "description": "d"},
        {"id": "CVE-2", "severity": "HIGH", "title": "Test2", "target": "t2", "description": "d2"},
    ]
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=AsyncMock(status_code=201, text="Created"))

    with patch("httpx.AsyncClient", return_value=mock_client):
        await notify_jira(findings, "https://jira.example.com", "token123")

    # Exactly one call for the CRITICAL finding
    assert mock_client.post.call_count == 1
    args, kwargs = mock_client.post.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer token123"
    assert "CVE-1" in kwargs["json"]["fields"]["summary"]


@pytest.mark.asyncio
async def test_notify_jira_no_critical():
    """No request should be made when there are no CRITICAL findings."""
    findings = [{"id": "CVE-3", "severity": "HIGH", "title": "T", "target": "t", "description": "d"}]
    mock_client = AsyncMock()
    with patch("httpx.AsyncClient", return_value=mock_client):
        await notify_jira(findings, "https://jira.example.com", "token123")
    mock_client.post.assert_not_called()


@pytest.mark.asyncio
async def test_notify_jira_request_failure_does_not_raise():
    """A non-201 response should not propagate as an exception."""
    findings = [{"id": "CVE-1", "severity": "CRITICAL", "title": "T", "target": "t", "description": "d"}]
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=AsyncMock(status_code=400, text="Bad request"))

    with patch("httpx.AsyncClient", return_value=mock_client):
        await notify_jira(findings, "https://jira.example.com", "token123")
    assert mock_client.post.call_count == 1  # request was made, function didn't crash


@pytest.mark.asyncio
async def test_notify_asana_missing_config():
    """Should not make any request when token or workspace is missing."""
    with patch("httpx.AsyncClient") as mock_async_client_cls:
        await notify_asana([], "", "")
        mock_async_client_cls.assert_not_called()
        await notify_asana([], "token", "")
        mock_async_client_cls.assert_not_called()
        await notify_asana([], "", "ws")
        mock_async_client_cls.assert_not_called()


@pytest.mark.asyncio
async def test_notify_asana_critical_only():
    findings = [
        {"id": "CVE-1", "severity": "CRITICAL", "title": "T", "target": "t", "description": "d"},
        {"id": "CVE-2", "severity": "MEDIUM", "title": "T", "target": "t", "description": "d"},
    ]
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=AsyncMock(status_code=201, text="Created"))

    with patch("httpx.AsyncClient", return_value=mock_client):
        await notify_asana(findings, "token_asana", "ws_id")

    assert mock_client.post.call_count == 1
    args, kwargs = mock_client.post.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer token_asana"
    assert "CVE-1" in kwargs["json"]["data"]["name"]


@pytest.mark.asyncio
async def test_notify_asana_no_critical():
    findings = [{"id": "CVE-3", "severity": "LOW", "title": "T", "target": "t", "description": "d"}]
    mock_client = AsyncMock()
    with patch("httpx.AsyncClient", return_value=mock_client):
        await notify_asana(findings, "token", "ws")
    mock_client.post.assert_not_called()


@pytest.mark.asyncio
async def test_notify_asana_request_failure_does_not_raise():
    findings = [{"id": "CVE-1", "severity": "CRITICAL", "title": "T", "target": "t", "description": "d"}]
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=AsyncMock(status_code=400, text="Bad request"))

    with patch("httpx.AsyncClient", return_value=mock_client):
        await notify_asana(findings, "token_asana", "ws_id")
    assert mock_client.post.call_count == 1
