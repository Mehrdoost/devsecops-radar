import re
from typing import Any
from urllib.parse import urlparse

import httpx
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def _validate_jira_url(url: str) -> str | None:
    """Ensure the Jira URL is a valid HTTPS endpoint without path traversal."""
    if not url:
        return None
    url = url.strip().rstrip("/")
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc:
            logger.error("Jira URL must use HTTPS and contain a valid hostname.")
            return None
        # Reject URLs with dangerous characters or extra paths beyond the base
        if not re.match(r"^https://[a-zA-Z0-9._-]+(?::\d+)?$", url):
            logger.error("Jira URL contains unexpected path or characters.")
            return None
        return url
    except Exception:
        return None


def _truncate(text: str, max_len: int = 1000) -> str:
    """Limit string length to prevent oversized payloads."""
    if text and len(text) > max_len:
        return text[:max_len] + "... [TRUNCATED]"
    return text


# ---------------------------------------------------------------------------
# Core notification functions (with retry)
# ---------------------------------------------------------------------------
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def _create_jira_issue(
    client: httpx.AsyncClient,
    base_url: str,
    finding: dict,
    api_token: str,
) -> None:
    """Attempt to create a single Jira issue (with retry on transient errors)."""
    summary = _truncate(f"[Pipeline Sentinel] {finding.get('id', 'UNKNOWN')}: {finding.get('title', 'No Title')}", 255)
    description_text = (
        f"Severity: {finding.get('severity', 'UNKNOWN')}\n"
        f"Target: {finding.get('target', 'UNKNOWN')}\n\n"
        f"{finding.get('description', '')}"
    )
    description_text = _truncate(description_text, 3000)

    payload = {
        "fields": {
            "project": {"key": "SEC"},
            "summary": summary,
            "description": description_text,
            "issuetype": {"name": "Bug"},
        }
    }
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    resp = await client.post(f"{base_url}/rest/api/2/issue", json=payload, headers=headers)
    if resp.status_code == 201:
        logger.info(f"Created Jira issue for {finding.get('id')}")
    else:
        # Avoid leaking token in logs: only log status and a snippet of the response
        logger.warning(
            f"Failed to create Jira issue for {finding.get('id')} (HTTP {resp.status_code}): "
            f"{resp.text[:200]}"
        )


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def _create_asana_task(
    client: httpx.AsyncClient,
    finding: dict,
    asana_token: str,
    workspace_gid: str,
) -> None:
    """Attempt to create a single Asana task (with retry on transient errors)."""
    name = _truncate(f"[Pipeline Sentinel] {finding.get('id', 'UNKNOWN')}: {finding.get('title', 'No Title')}", 255)
    notes = (
        f"Severity: {finding.get('severity', 'UNKNOWN')}\n"
        f"Target: {finding.get('target', 'UNKNOWN')}\n\n"
        f"{finding.get('description', '')}"
    )
    notes = _truncate(notes, 3000)

    payload = {
        "data": {
            "workspace": workspace_gid,
            "name": name,
            "notes": notes,
        }
    }
    headers = {"Authorization": f"Bearer {asana_token}", "Content-Type": "application/json"}
    resp = await client.post("https://app.asana.com/api/1.0/tasks", json=payload, headers=headers)
    if resp.status_code == 201:
        logger.info(f"Created Asana task for {finding.get('id')}")
    else:
        logger.warning(
            f"Failed to create Asana task for {finding.get('id')} (HTTP {resp.status_code}): "
            f"{resp.text[:200]}"
        )


# ---------------------------------------------------------------------------
# Public functions (called from CLI)
# ---------------------------------------------------------------------------
async def notify_jira(
    findings: list[dict[str, Any]],
    jira_url: str,
    api_token: str,
) -> None:
    """Send CRITICAL findings to Jira."""
    safe_url = _validate_jira_url(jira_url)
    if not safe_url:
        logger.warning("Jira URL invalid. Skipping Jira notification.")
        return
    if not api_token:
        logger.warning("Jira API token not configured. Skipping Jira notification.")
        return

    async with httpx.AsyncClient() as client:
        for f in findings:
            if str(f.get("severity", "")).upper() == "CRITICAL":
                try:
                    await _create_jira_issue(client, safe_url, f, api_token)
                except Exception as e:
                    logger.error(f"Jira notification ultimately failed for {f.get('id')}: {e}")


async def notify_asana(
    findings: list[dict[str, Any]],
    asana_token: str,
    workspace_gid: str,
) -> None:
    """Send CRITICAL findings to Asana."""
    if not asana_token or not workspace_gid:
        logger.warning("Asana token or workspace GID not configured. Skipping Asana notification.")
        return
    # Basic validation of workspace_gid (must be a non‑empty string of digits)
    if not re.match(r"^\d+$", workspace_gid):
        logger.error("Invalid Asana workspace GID format. Skipping.")
        return

    async with httpx.AsyncClient() as client:
        for f in findings:
            if str(f.get("severity", "")).upper() == "CRITICAL":
                try:
                    await _create_asana_task(client, f, asana_token, workspace_gid)
                except Exception as e:
                    logger.error(f"Asana notification ultimately failed for {f.get('id')}: {e}")
