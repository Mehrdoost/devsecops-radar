from unittest.mock import AsyncMock, patch

import httpx
import pytest

from devsecops_radar.core.notifier import (
    _create_asana_task,
    _create_jira_issue,
    _truncate,
    _validate_jira_url,
    logger,
    notify_asana,
    notify_jira,
)


# ------------------------------------------------------------
# Tests for _validate_jira_url
# ------------------------------------------------------------
class TestValidateJiraUrl:
    def test_valid_url(self):
        assert _validate_jira_url("https://mycompany.atlassian.net") == "https://mycompany.atlassian.net"

    def test_trailing_slash_removed(self):
        assert _validate_jira_url("https://mycompany.atlassian.net/") == "https://mycompany.atlassian.net"

    def test_empty_url_returns_none(self):
        assert _validate_jira_url("") is None
        assert _validate_jira_url(None) is None

    def test_non_https_scheme(self):
        with patch.object(logger, "error") as mock_log:
            assert _validate_jira_url("http://mycompany.atlassian.net") is None
            mock_log.assert_called_with("Jira URL must use HTTPS and contain a valid hostname.")

    def test_no_hostname(self):
        with patch.object(logger, "error") as mock_log:
            assert _validate_jira_url("https:///path") is None
            mock_log.assert_called_with("Jira URL must use HTTPS and contain a valid hostname.")

    def test_path_traversal_rejected(self):
        with patch.object(logger, "error") as mock_log:
            assert _validate_jira_url("https://mycompany.atlassian.net/rest/api/2/issue") is None
            mock_log.assert_called_with("Jira URL contains unexpected path or characters.")

    def test_special_characters_rejected(self):
        with patch.object(logger, "error") as mock_log:
            assert _validate_jira_url("https://mycompany.atlassian.net@evil.com") is None
            mock_log.assert_called_with("Jira URL contains unexpected path or characters.")

    def test_exception_returns_none(self):
        # Force urlparse to raise by passing something weird, but we'll mock urlparse
        with patch("devsecops_radar.core.notifier.urlparse", side_effect=Exception("boom")):
            assert _validate_jira_url("anything") is None


# ------------------------------------------------------------
# Tests for _truncate
# ------------------------------------------------------------
class TestTruncate:
    def test_short_text(self):
        assert _truncate("hello", 10) == "hello"

    def test_exact_length(self):
        assert _truncate("1234567890", 10) == "1234567890"

    def test_long_text(self):
        assert _truncate("1234567890abc", 10) == "1234567890... [TRUNCATED]"

    def test_none_text(self):
        assert _truncate(None, 10) is None  # because function checks "if text and len(text) > max_len", None is falsy -> returns text (None)


# ------------------------------------------------------------
# Tests for _create_jira_issue
# ------------------------------------------------------------
class TestCreateJiraIssue:
    @pytest.mark.asyncio
    async def test_success(self):
        client = AsyncMock()
        client.post.return_value.status_code = 201
        finding = {"id": "F-1", "title": "SQLi", "severity": "CRITICAL", "target": "app.py", "description": "desc"}
        with patch.object(logger, "info") as mock_info:
            await _create_jira_issue(client, "https://jira.example.com", finding, "token")
            mock_info.assert_called_with("Created Jira issue for F-1")
            # Verify payload
            call_args = client.post.call_args
            assert call_args[0][0] == "https://jira.example.com/rest/api/2/issue"
            payload = call_args[1]["json"]
            assert "fields" in payload
            assert payload["fields"]["project"]["key"] == "SEC"
            assert payload["fields"]["issuetype"]["name"] == "Bug"
            # summary truncated to 255
            assert len(payload["fields"]["summary"]) <= 255
            # description truncated to 3000
            assert len(payload["fields"]["description"]) <= 3000

    @pytest.mark.asyncio
    async def test_failure_non_201(self):
        client = AsyncMock()
        client.post.return_value.status_code = 400
        client.post.return_value.text = "Bad Request"
        finding = {"id": "F-1", "title": "SQLi", "severity": "HIGH"}
        with patch.object(logger, "warning") as mock_warn:
            await _create_jira_issue(client, "https://jira.example.com", finding, "token")
            mock_warn.assert_called_once()
            assert "Failed to create Jira issue" in mock_warn.call_args[0][0]
            # Ensure token is not leaked (we check that the log does not contain 'token')
            assert "token" not in mock_warn.call_args[0][0]

    @pytest.mark.asyncio
    async def test_retry_on_httpx_error(self):
        client = AsyncMock()
        # First call raises, second succeeds
        client.post.side_effect = [httpx.HTTPError("timeout"), AsyncMock(status_code=201)]
        finding = {"id": "F-2", "title": "XSS"}
        with patch.object(logger, "info") as mock_info:
            await _create_jira_issue(client, "https://jira.example.com", finding, "token")
            assert client.post.call_count == 2
            mock_info.assert_called_once()


# ------------------------------------------------------------
# Tests for _create_asana_task
# ------------------------------------------------------------
class TestCreateAsanaTask:
    @pytest.mark.asyncio
    async def test_success(self):
        client = AsyncMock()
        client.post.return_value.status_code = 201
        finding = {"id": "F-1", "title": "SQLi", "severity": "CRITICAL", "target": "app.py", "description": "desc"}
        with patch.object(logger, "info") as mock_info:
            await _create_asana_task(client, finding, "token", "12345")
            mock_info.assert_called_with("Created Asana task for F-1")
            call_args = client.post.call_args
            assert call_args[0][0] == "https://app.asana.com/api/1.0/tasks"
            payload = call_args[1]["json"]
            assert payload["data"]["workspace"] == "12345"
            assert len(payload["data"]["name"]) <= 255
            assert len(payload["data"]["notes"]) <= 3000

    @pytest.mark.asyncio
    async def test_failure_non_201(self):
        client = AsyncMock()
        client.post.return_value.status_code = 400
        client.post.return_value.text = "Bad Request"
        finding = {"id": "F-1", "title": "SQLi", "severity": "LOW"}
        with patch.object(logger, "warning") as mock_warn:
            await _create_asana_task(client, finding, "token", "12345")
            mock_warn.assert_called_once()
            assert "Failed to create Asana task" in mock_warn.call_args[0][0]

    @pytest.mark.asyncio
    async def test_retry_on_httpx_error(self):
        client = AsyncMock()
        client.post.side_effect = [httpx.HTTPError("timeout"), AsyncMock(status_code=201)]
        finding = {"id": "F-3", "title": "RCE"}
        with patch.object(logger, "info") as mock_info:
            await _create_asana_task(client, finding, "token", "12345")
            assert client.post.call_count == 2
            mock_info.assert_called_once()


# ------------------------------------------------------------
# Tests for notify_jira
# ------------------------------------------------------------
class TestNotifyJira:
    @pytest.mark.asyncio
    async def test_url_invalid_skips(self):
        findings = [{"id": "1", "severity": "CRITICAL"}]
        with patch("devsecops_radar.core.notifier._validate_jira_url", return_value=None), \
             patch.object(logger, "warning") as mock_warn:
            await notify_jira(findings, "bad_url", "token")
            mock_warn.assert_called_with("Jira URL invalid. Skipping Jira notification.")

    @pytest.mark.asyncio
    async def test_no_token_skips(self):
        findings = [{"id": "1", "severity": "CRITICAL"}]
        with patch("devsecops_radar.core.notifier._validate_jira_url", return_value="https://jira.com"), \
             patch.object(logger, "warning") as mock_warn:
            await notify_jira(findings, "url", "")
            mock_warn.assert_called_with("Jira API token not configured. Skipping Jira notification.")

    @pytest.mark.asyncio
    async def test_only_critical_processed(self):
        findings = [
            {"id": "1", "severity": "HIGH"},
            {"id": "2", "severity": "CRITICAL"},
            {"id": "3", "severity": "LOW"},
        ]
        with patch("devsecops_radar.core.notifier._validate_jira_url", return_value="https://jira.com"), \
             patch("devsecops_radar.core.notifier._create_jira_issue", new_callable=AsyncMock) as mock_create, \
             patch("httpx.AsyncClient"):
            await notify_jira(findings, "url", "token")
            assert mock_create.call_count == 1
            # only id=2 was called
            called_finding_id = mock_create.call_args[0][2]["id"]
            assert called_finding_id == "2"

    @pytest.mark.asyncio
    async def test_jira_create_exception_is_logged(self):
        findings = [{"id": "X", "severity": "CRITICAL"}]
        with patch("devsecops_radar.core.notifier._validate_jira_url", return_value="https://jira.com"), \
             patch("devsecops_radar.core.notifier._create_jira_issue", side_effect=Exception("fail")), \
             patch("httpx.AsyncClient"), \
             patch.object(logger, "error") as mock_error:
            await notify_jira(findings, "url", "token")
            mock_error.assert_called_with("Jira notification ultimately failed for X: fail")


# ------------------------------------------------------------
# Tests for notify_asana
# ------------------------------------------------------------
class TestNotifyAsana:
    @pytest.mark.asyncio
    async def test_missing_credentials(self):
        findings = [{"id": "1", "severity": "CRITICAL"}]
        with patch.object(logger, "warning") as mock_warn:
            await notify_asana(findings, "", "")
            mock_warn.assert_called_with("Asana token or workspace GID not configured. Skipping Asana notification.")

    @pytest.mark.asyncio
    async def test_invalid_workspace_gid(self):
        findings = [{"id": "1", "severity": "CRITICAL"}]
        with patch.object(logger, "error") as mock_error:
            await notify_asana(findings, "token", "abc")
            mock_error.assert_called_with("Invalid Asana workspace GID format. Skipping.")

    @pytest.mark.asyncio
    async def test_only_critical_processed(self):
        findings = [
            {"id": "A", "severity": "MEDIUM"},
            {"id": "B", "severity": "CRITICAL"},
        ]
        with patch("devsecops_radar.core.notifier._create_asana_task", new_callable=AsyncMock) as mock_create, \
             patch("httpx.AsyncClient"):
            await notify_asana(findings, "token", "12345")
            assert mock_create.call_count == 1
            called_id = mock_create.call_args[0][1]["id"]
            assert called_id == "B"

    @pytest.mark.asyncio
    async def test_asana_create_exception_is_logged(self):
        findings = [{"id": "Y", "severity": "CRITICAL"}]
        with patch("devsecops_radar.core.notifier._create_asana_task", side_effect=Exception("fail")), \
             patch("httpx.AsyncClient"), \
             patch.object(logger, "error") as mock_error:
            await notify_asana(findings, "token", "12345")
            mock_error.assert_called_with("Asana notification ultimately failed for Y: fail")
