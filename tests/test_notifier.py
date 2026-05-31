from unittest.mock import AsyncMock, patch

import pytest

from devsecops_radar.core.notifier import notify_asana, notify_jira


@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_notify_jira_creates_issues(mock_post):
    findings = [
        {"id": "CVE-1", "severity": "CRITICAL", "title": "Test", "target": "t", "description": "desc"},
        {"id": "CVE-2", "severity": "HIGH", "title": "Test2", "target": "t2", "description": "desc2"},
    ]
    mock_post.return_value.status_code = 201
    mock_post.return_value.text = "Created"

    await notify_jira(findings, "https://jira.example.com", "token123")

    # only one CRITICAL finding -> one request
    assert mock_post.call_count == 1

    call_args = mock_post.call_args[1]
    assert call_args["headers"]["Authorization"] == "Bearer token123"
    assert "CVE-1" in call_args["json"]["fields"]["summary"]


@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_notify_jira_no_critical(mock_post):
    findings = [{"id": "CVE-2", "severity": "HIGH", "title": "T", "target": "t", "description": "d"}]
    await notify_jira(findings, "https://jira.example.com", "token123")
    mock_post.assert_not_called()


@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_notify_jira_missing_config(mock_post):
    await notify_jira([], "", "")
    mock_post.assert_not_called()


@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_notify_jira_request_failure_does_not_raise(mock_post):
    findings = [{"id": "CVE-1", "severity": "CRITICAL", "title": "T", "target": "t", "description": "d"}]
    mock_post.return_value.status_code = 400
    mock_post.return_value.text = "Bad request"
    # Should not raise
    await notify_jira(findings, "https://jira.example.com", "token123")
    assert mock_post.call_count == 1


@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_notify_asana_creates_tasks(mock_post):
    findings = [{"id": "CVE-3", "severity": "CRITICAL", "title": "T", "target": "t", "description": "d"}]
    mock_post.return_value.status_code = 201
    mock_post.return_value.text = "Created"

    await notify_asana(findings, "token_asana", "12345")

    assert mock_post.call_count == 1
    call_args = mock_post.call_args[1]
    assert call_args["headers"]["Authorization"] == "Bearer token_asana"
    assert "CVE-3" in call_args["json"]["data"]["name"]


@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_notify_asana_no_critical(mock_post):
    findings = [{"id": "CVE-4", "severity": "LOW", "title": "T", "target": "t", "description": "d"}]
    await notify_asana(findings, "token", "ws")
    mock_post.assert_not_called()


@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_notify_asana_missing_config(mock_post):
    await notify_asana([], "", "")
    mock_post.assert_not_called()


@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_notify_asana_request_failure_does_not_raise(mock_post):
    findings = [{"id": "CVE-1", "severity": "CRITICAL", "title": "T", "target": "t", "description": "d"}]
    mock_post.return_value.status_code = 400
    mock_post.return_value.text = "Bad request"
    # Should not raise
    await notify_asana(findings, "token_asana", "ws_id")
    assert mock_post.call_count == 1
