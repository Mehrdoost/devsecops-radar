from typing import Any

import httpx
from loguru import logger


async def notify_jira(findings: list[dict[str, Any]], jira_url: str, api_token: str) -> None:
    if not jira_url or not api_token:
        logger.warning("Jira URL or API token not configured. Skipping Jira notification.")
        return

    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient() as client:
        for f in findings:
            if f.get("severity") == "CRITICAL":
                payload = {
                    "fields": {
                        "project": {"key": "SEC"},
                        "summary": f"[Pipeline Sentinel] {f['id']}: {f['title']}",
                        "description": (
    f"Severity: {f['severity']}\n"
    f"Target: {f['target']}\n\n"
    f"{f.get('description', '')}"
),
                        "issuetype": {"name": "Bug"}
                    }
                }
                try:
                    resp = await client.post(f"{jira_url}/rest/api/2/issue", json=payload, headers=headers)
                    if resp.status_code == 201:
                        logger.info(f"Created Jira issue for {f['id']}")
                    else:
                        logger.warning(f"Failed to create Jira issue for {f['id']}: {resp.text}")
                except Exception as e:
                    logger.error(f"Jira notification failed: {e}")


async def notify_asana(findings: list[dict[str, Any]], asana_token: str, workspace_gid: str) -> None:
    if not asana_token or not workspace_gid:
        logger.warning("Asana token or workspace not configured. Skipping Asana notification.")
        return

    headers = {"Authorization": f"Bearer {asana_token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient() as client:
        for f in findings:
            if f.get("severity") == "CRITICAL":
                payload = {
                    "data": {
                        "workspace": workspace_gid,
                        "name": f"[Pipeline Sentinel] {f['id']}: {f['title']}",
                        "notes": f"Severity: {f['severity']}\nTarget: {f['target']}\n\n{f.get('description', '')}"
                    }
                }
                try:
                    resp = await client.post("https://app.asana.com/api/1.0/tasks", json=payload, headers=headers)
                    if resp.status_code == 201:
                        logger.info(f"Created Asana task for {f['id']}")
                    else:
                        logger.warning(f"Failed to create Asana task for {f['id']}: {resp.text}")
                except Exception as e:
                    logger.error(f"Asana notification failed: {e}")
