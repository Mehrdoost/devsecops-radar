# devsecops_radar/core/notifier.py
"""
Jira and Asana notification dispatchers with strict output sanitization
and polite rate‑limiting avoidance.
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx
from loguru import logger
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential


# ---------------------------------------------------------------------------
# URL validation (defence‑in‑depth – primary check is in settings.py)
# ---------------------------------------------------------------------------
def _validate_jira_url(url: str) -> str | None:
    if not url:
        return None
    url = url.strip().rstrip("/")
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            logger.error("Jira URL must use HTTPS.")
            return None
        if not parsed.netloc:
            logger.error("Jira URL has no hostname.")
            return None
        if " " in url or ";" in url:
            logger.error("Jira URL contains invalid characters.")
            return None
        return url
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------
def _truncate(text: str, max_len: int = 1000) -> str:
    if text and len(text) > max_len:
        return text[:max_len] + "... [TRUNCATED]"
    return text


def _sanitize_json_string(text: str) -> str:
    """Remove null bytes and ASCII control characters (except newline/tab)."""
    if not isinstance(text, str):
        return ""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)


# ---------------------------------------------------------------------------
# Custom retry condition
# ---------------------------------------------------------------------------
def _is_retryable(exception: BaseException) -> bool:
    if isinstance(exception, httpx.HTTPStatusError):
        code = exception.response.status_code
        return code == 429 or (500 <= code < 600)
    if isinstance(exception, (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout, httpx.TimeoutException)):
        return True
    return False


# ---------------------------------------------------------------------------
# Core notification functions (with sanitization)
# ---------------------------------------------------------------------------
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(_is_retryable),
)
async def _create_jira_issue(
    client: httpx.AsyncClient,
    base_url: str,
    finding: dict,
    api_token: str,
    project_key: str,
    issue_type: str,
) -> bool:
    """Return True if issue was created successfully."""
    title_raw = finding.get("title", "No Title")
    fid = finding.get("id", "UNKNOWN")

    summary = _truncate(
        f"[Pipeline Sentinel] {fid}: {title_raw}",
        255,
    )
    summary = _sanitize_json_string(summary)

    description_text = (
        f"Severity: {finding.get('severity', 'UNKNOWN')}\n"
        f"Target: {finding.get('target', 'UNKNOWN')}\n\n"
        f"{finding.get('description', '')}"
    )
    description_text = _sanitize_json_string(_truncate(description_text, 2000))

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description_text,
            "issuetype": {"name": issue_type},
        }
    }
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    resp = await client.post(
        f"{base_url}/rest/api/2/issue", json=payload, headers=headers
    )
    if resp.status_code == 201:
        logger.info(f"Created Jira issue for {fid}")
        return True
    else:
        logger.warning(
            f"Failed to create Jira issue for {fid} "
            f"(HTTP {resp.status_code}): {resp.text[:200]}"
        )
        return False


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(_is_retryable),
)
async def _create_asana_task(
    client: httpx.AsyncClient,
    finding: dict,
    asana_token: str,
    workspace_gid: str,
) -> bool:
    """Return True if task was created successfully."""
    title_raw = finding.get("title", "No Title")
    fid = finding.get("id", "UNKNOWN")

    name = _truncate(
        f"[Pipeline Sentinel] {fid}: {title_raw}",
        255,
    )
    name = _sanitize_json_string(name)

    notes = (
        f"Severity: {finding.get('severity', 'UNKNOWN')}\n"
        f"Target: {finding.get('target', 'UNKNOWN')}\n\n"
        f"{finding.get('description', '')}"
    )
    notes = _sanitize_json_string(_truncate(notes, 2000))

    payload = {
        "data": {
            "workspace": workspace_gid,
            "name": name,
            "notes": notes,
        }
    }
    headers = {
        "Authorization": f"Bearer {asana_token}",
        "Content-Type": "application/json",
    }
    resp = await client.post(
        "https://app.asana.com/api/1.0/tasks", json=payload, headers=headers
    )
    if resp.status_code == 201:
        logger.info(f"Created Asana task for {fid}")
        return True
    else:
        logger.warning(
            f"Failed to create Asana task for {fid} "
            f"(HTTP {resp.status_code}): {resp.text[:200]}"
        )
        return False


# ---------------------------------------------------------------------------
# Public functions (with inter‑request delay)
# ---------------------------------------------------------------------------
async def notify_jira(
    findings: list[dict[str, Any]],
    jira_url: str,
    api_token: str,
) -> None:
    safe_url = _validate_jira_url(jira_url)
    if not safe_url:
        logger.warning("Jira URL invalid. Skipping Jira notification.")
        return
    if not api_token:
        logger.warning("Jira API token not configured. Skipping Jira notification.")
        return

    project_key = os.environ.get("JIRA_PROJECT_KEY", "SEC")
    issue_type = os.environ.get("JIRA_ISSUE_TYPE", "Bug")

    async with httpx.AsyncClient() as client:
        for f in findings:
            if str(f.get("severity", "")).upper() == "CRITICAL":
                try:
                    success = await _create_jira_issue(
                        client, safe_url, f, api_token, project_key, issue_type
                    )
                    if not success:
                        logger.error(f"Jira issue creation ultimately failed for {f.get('id')}")
                except Exception as e:
                    logger.error(f"Jira notification ultimately failed for {f.get('id')}: {e}")
                # Avoid hammering the API
                await asyncio.sleep(0.5)


async def notify_asana(
    findings: list[dict[str, Any]],
    asana_token: str,
    workspace_gid: str,
) -> None:
    if not asana_token or not workspace_gid:
        logger.warning("Asana token or workspace GID not configured. Skipping Asana notification.")
        return
    if not re.match(r"^\d+$", workspace_gid):
        logger.error("Invalid Asana workspace GID format. Skipping.")
        return

    async with httpx.AsyncClient() as client:
        for f in findings:
            if str(f.get("severity", "")).upper() == "CRITICAL":
                try:
                    success = await _create_asana_task(client, f, asana_token, workspace_gid)
                    if not success:
                        logger.error(f"Asana task creation ultimately failed for {f.get('id')}")
                except Exception as e:
                    logger.error(f"Asana notification ultimately failed for {f.get('id')}: {e}")
                await asyncio.sleep(0.5)
