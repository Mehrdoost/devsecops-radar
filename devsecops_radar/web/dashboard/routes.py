# devsecops_radar/web/dashboard/routes.py
"""
Dashboard routes – unified data source (database), safe report generation,
asynchronous notification dispatching, strict output redaction,
and automatic patch application.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import threading
from datetime import UTC, datetime, timedelta
from html import escape as html_escape
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, render_template, request, send_file
from loguru import logger

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.database import (
    get_findings_paginated,
    get_session,
)
from devsecops_radar.core.models import Finding, Scan
from devsecops_radar.core.path_security import safe_read_open
from devsecops_radar.core.rag import rag_search
from devsecops_radar.core.remediation import apply_patch
from devsecops_radar.core.reporting import (
    _build_pdf_elements,
    redact_sensitive,
)
from devsecops_radar.web.sentry.routes import get_live_snapshot

dashboard_bp = Blueprint("dashboard", __name__)

_MAX_FINDINGS_RETURN = 5000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _all_findings() -> list[dict[str, Any]]:
    with get_session() as session:
        rows = session.query(Finding).order_by(Finding.id.desc()).limit(_MAX_FINDINGS_RETURN).all()
        return [
            {
                "id": f.rule_id,
                "tool": f.tool,
                "severity": f.severity,
                "target": f.target,
                "title": redact_sensitive(f.title or ""),
                "description": redact_sensitive(f.description or ""),
                "line": f.line,
            }
            for f in rows
        ]


def _findings_from_db(limit: int | None = None) -> list[dict[str, Any]]:
    with get_session() as session:
        q = session.query(Finding).order_by(Finding.id.desc())
        if limit is not None:
            q = q.limit(limit)
        rows = q.all()
        return [
            {
                "id": f.rule_id,
                "tool": f.tool,
                "severity": f.severity,
                "target": f.target,
                "title": redact_sensitive(f.title or ""),
                "description": redact_sensitive(f.description or ""),
                "line": f.line,
            }
            for f in rows
        ]


def _latest_ai_summary() -> dict[str, Any]:
    with get_session() as session:
        scan = session.query(Scan).order_by(Scan.id.desc()).first()
        if not scan or not scan.ai_summary_json:
            return {}
        try:
            return json.loads(scan.ai_summary_json)
        except (json.JSONDecodeError, TypeError):
            return {}


def _ai_summary_for_scan(scan_id: int) -> dict[str, Any]:
    with get_session() as session:
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or not scan.ai_summary_json:
            return {}
        try:
            return json.loads(scan.ai_summary_json)
        except (json.JSONDecodeError, TypeError):
            return {}


def _critical_count_from_db() -> int:
    with get_session() as session:
        return session.query(Finding).filter(Finding.severity == "CRITICAL").count()


def _findings_by_ids(ids: list[str]) -> list[dict[str, Any]]:
    if not ids:
        return []
    with get_session() as session:
        rows = session.query(Finding).filter(Finding.rule_id.in_(ids)).all()
        return [
            {
                "id": f.rule_id,
                "tool": f.tool,
                "severity": f.severity,
                "target": f.target,
                "title": redact_sensitive(f.title or ""),
                "description": redact_sensitive(f.description or ""),
                "line": f.line,
            }
            for f in rows
        ]


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@dashboard_bp.route("/")
def index():
    return render_template("index.html")


@dashboard_bp.route("/api/findings")
@require_any_auth
def api_findings():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    if per_page > 1000:
        all_data = _all_findings()
        return jsonify({
            "total": len(all_data),
            "page": 1,
            "per_page": len(all_data),
            "data": all_data,
        })
    return jsonify(get_findings_paginated(page, per_page))


@dashboard_bp.route("/api/severity-counts")
@require_any_auth
def severity_counts():
    with get_session() as session:
        from sqlalchemy import func
        rows = session.query(Finding.severity, func.count()).group_by(Finding.severity).all()
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for sev, cnt in rows:
            key = str(sev).upper()
            if key in counts:
                counts[key] = cnt
        return jsonify(counts)


@dashboard_bp.route("/api/history")
@require_any_auth
def api_history():
    with get_session() as session:
        scans_query = session.query(Scan).order_by(Scan.timestamp.desc())
        range_filter = request.args.get("range", "all")
        now = datetime.now(UTC)
        if range_filter == "week":
            since = now - timedelta(days=7)
            scans_query = scans_query.filter(Scan.timestamp >= since)
        elif range_filter == "month":
            since = now - timedelta(days=30)
            scans_query = scans_query.filter(Scan.timestamp >= since)
        elif range_filter == "year":
            since = now - timedelta(days=365)
            scans_query = scans_query.filter(Scan.timestamp >= since)

        scans = scans_query.all()
        result = []
        for s in scans:
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in s.findings:
                sev = str(f.severity).upper()
                counts[sev] = counts.get(sev, 0) + 1
            result.append({
                "timestamp": s.timestamp.isoformat() if s.timestamp else None,
                "risk_score": s.risk_score,
                "critical": counts["CRITICAL"],
                "high": counts["HIGH"],
                "medium": counts["MEDIUM"],
                "low": counts["LOW"],
            })
        return jsonify(result)


@dashboard_bp.route("/api/scanner-status")
@require_any_auth
def scanner_status():
    scanners = ["trivy", "semgrep", "poutine", "zizmor", "gitleaks"]
    status = {name: bool(_which(name)) for name in scanners}
    return jsonify(status)


def _which(cmd: str) -> str | None:
    import shutil
    return shutil.which(cmd)


@dashboard_bp.route("/api/live-feed")
@require_any_auth
def live_feed():
    return jsonify(get_live_snapshot())


@dashboard_bp.route("/api/policy-status")
@require_any_auth
def policy_status():
    policy_path = Path("policy.json")
    if not policy_path.exists():
        return jsonify({"status": "no_policy"})
    try:
        with safe_read_open(policy_path, base_dir=Path.cwd()) as f:
            policy = json.load(f)
        max_crit = policy.get("max_critical")
        if max_crit is None:
            return jsonify({"status": "invalid_policy"})
        crit_count = _critical_count_from_db()
        return jsonify({
            "max_critical": max_crit,
            "current_critical": crit_count,
            "violated": crit_count > max_crit,
        })
    except Exception as e:
        logger.error(f"Failed to read policy.json: {e}")
        return jsonify({"status": "error"})


def _run_async_in_thread(coro):
    def runner():
        try:
            asyncio.run(coro)
        except Exception as e:
            logger.error(f"Asynchronous notification failed: {e}")
    t = threading.Thread(target=runner, daemon=True)
    t.start()


@dashboard_bp.route("/api/notify-jira", methods=["POST"])
@require_any_auth
def notify_jira_endpoint():
    data = request.get_json(force=True)
    finding_ids = data.get("finding_ids", [])
    if not isinstance(finding_ids, list):
        return jsonify({"error": "finding_ids must be a list"}), 400
    findings = _findings_by_ids(finding_ids)
    if not findings:
        return jsonify({"error": "No matching findings provided"}), 400
    jira_url = os.environ.get("JIRA_URL")
    jira_token = os.environ.get("JIRA_TOKEN")
    if not jira_url or not jira_token:
        return jsonify({"error": "JIRA_URL and JIRA_TOKEN must be set"}), 500
    from devsecops_radar.core.notifier import notify_jira
    _run_async_in_thread(notify_jira(findings, jira_url, jira_token))
    return jsonify({"status": "dispatched"})


@dashboard_bp.route("/api/notify-asana", methods=["POST"])
@require_any_auth
def notify_asana_endpoint():
    data = request.get_json(force=True)
    finding_ids = data.get("finding_ids", [])
    if not isinstance(finding_ids, list):
        return jsonify({"error": "finding_ids must be a list"}), 400
    findings = _findings_by_ids(finding_ids)
    if not findings:
        return jsonify({"error": "No matching findings provided"}), 400
    asana_token = os.environ.get("ASANA_TOKEN")
    asana_workspace = os.environ.get("ASANA_WORKSPACE")
    if not asana_token or not asana_workspace:
        return jsonify({"error": "ASANA_TOKEN and ASANA_WORKSPACE must be set"}), 500
    from devsecops_radar.core.notifier import notify_asana
    _run_async_in_thread(notify_asana(findings, asana_token, asana_workspace))
    return jsonify({"status": "dispatched"})


@dashboard_bp.route("/api/rag")
@require_any_auth
def api_rag():
    q = request.args.get("q", "")
    if not q:
        return jsonify([])
    return jsonify(rag_search(q))


@dashboard_bp.route("/api/simulate", methods=["POST"])
@require_any_auth
def api_simulate():
    data = request.get_json(force=True)
    finding_ids = data.get("finding_ids", [])
    if not isinstance(finding_ids, list):
        return jsonify({"error": "finding_ids must be a list"}), 400
    selected = _findings_by_ids(finding_ids)
    if not selected:
        return jsonify({"error": "Not found"}), 404
    from devsecops_radar.core.attack_simulation import (
        run_sandboxed_poc,
        simulate_attack,
    )
    scripts = []
    descs = []
    last_artifact = None
    for f in selected:
        artifact = simulate_attack(f)
        if artifact:
            try:
                with safe_read_open(artifact.script_path, base_dir=artifact.temp_dir) as sf:
                    scripts.append(sf.read())
                last_artifact = artifact
            except Exception as e:
                logger.warning(f"Could not read simulation script {artifact.script_path}: {e}")
        descs.append(f"{f.get('id')}: {f.get('title')}")
    full_script = "\n".join(scripts)
    desc = " → ".join(descs)
    sandbox_output = None
    if last_artifact:
        try:
            sandbox_output = run_sandboxed_poc(last_artifact)
        except Exception:
            logger.warning("Sandbox execution failed silently.", exc_info=True)
    return jsonify({
        "script": full_script,
        "description": desc,
        "sandbox_output": sandbox_output,
    })


@dashboard_bp.route("/api/report")
@require_any_auth
def api_report():
    fmt = request.args.get("format", "pdf")
    framework = request.args.get("framework")
    findings = _all_findings()
    ai_summary = _latest_ai_summary()
    if fmt == "json":
        data = json.dumps({"findings": findings, "ai_summary": ai_summary}, indent=2)
        return send_file(
            io.BytesIO(data.encode()),
            mimetype="application/json",
            as_attachment=True,
            download_name="report.json",
        )
    if fmt == "html":
        html_parts = [
            "<html><head><title>Pipeline Sentinel Report</title></head><body>",
            "<h1>Pipeline Sentinel Security Report</h1>",
        ]
        if framework:
            html_parts.append(f"<h2>Compliance Framework: {html_escape(framework)}</h2>")
        summary = ai_summary.get("executive_summary", "")
        if summary:
            html_parts.append("<h2>Executive Summary</h2>")
            html_parts.append(f"<p>{html_escape(redact_sensitive(summary))}</p>")
        html_parts.append(
            "<h2>Findings</h2><table border='1'><tr>"
            "<th>Tool</th><th>ID</th><th>Severity</th><th>Target</th><th>Title</th></tr>"
        )
        for f in findings:
            html_parts.append(
                f"<tr><td>{html_escape(f['tool'])}</td>"
                f"<td>{html_escape(f['id'])}</td>"
                f"<td>{html_escape(f['severity'])}</td>"
                f"<td>{html_escape(f['target'])}</td>"
                f"<td>{html_escape(redact_sensitive(f.get('title', '')))}</td></tr>"
            )
        html_parts.append("</table></body></html>")
        html_content = "\n".join(html_parts)
        return send_file(
            io.BytesIO(html_content.encode()),
            mimetype="text/html",
            as_attachment=True,
            download_name="report.html",
        )
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    elements = _build_pdf_elements(findings, ai_summary, framework=framework)
    doc.build(elements)
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="pipeline_sentinel_report.pdf",
    )


@dashboard_bp.route("/api/scans-with-ai")
@require_any_auth
def scans_with_ai():
    with get_session() as session:
        scans = session.query(Scan).filter(
            Scan.ai_summary_json.isnot(None)
        ).order_by(Scan.timestamp.desc()).limit(20).all()
        return jsonify([
            {"scan_id": s.id, "timestamp": s.timestamp.isoformat() if s.timestamp else None}
            for s in scans
        ])


@dashboard_bp.route("/api/summary/<int:scan_id>")
@require_any_auth
def api_summary_for_scan(scan_id):
    ai_summary = _ai_summary_for_scan(scan_id)
    if not ai_summary:
        return jsonify({})
    with get_session() as session:
        total_findings = session.query(Finding).filter(Finding.scan_id == scan_id).count()
        critical_count = session.query(Finding).filter(
            Finding.scan_id == scan_id,
            Finding.severity == "CRITICAL",
        ).count()
    ai_summary["total_findings"] = total_findings
    ai_summary["critical_findings"] = critical_count
    return jsonify(_sanitize_ai_summary(ai_summary))


def _sanitize_ai_summary(ai_summary: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in ai_summary.items():
        if isinstance(value, str):
            sanitized[key] = html_escape(redact_sensitive(value))
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_ai_summary(value)
        elif isinstance(value, list):
            sanitized[key] = [
                _sanitize_ai_summary(item) if isinstance(item, dict)
                else html_escape(redact_sensitive(item)) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            sanitized[key] = value
    return sanitized


# ---------------------------------------------------------------------------
# NEW: Apply AI‑suggested fix
# ---------------------------------------------------------------------------
@dashboard_bp.route("/api/apply-fix", methods=["POST"])
@require_any_auth
def apply_fix_endpoint():
    data = request.get_json(force=True)
    finding_id = data.get("finding_id")
    patch_content = data.get("patch_content")

    if not finding_id or not isinstance(finding_id, str):
        return jsonify({"error": "finding_id is required"}), 400
    if not patch_content or not isinstance(patch_content, str):
        return jsonify({"error": "patch_content is required"}), 400

    # Find the actual finding in the database
    with get_session() as session:
        finding = session.query(Finding).filter(Finding.rule_id == finding_id).first()
        if not finding:
            return jsonify({"error": "Finding not found"}), 404

        # Build a minimal dict that apply_patch expects
        finding_dict = {
            "target": finding.target,
            "line": finding.line,
            "evidence": None,   # evidence check is optional
        }

    # Apply the patch using the core remediation module
    try:
        success = apply_patch(finding_dict, patch_content, require_evidence=False)
        if success:
            logger.info(f"Patch applied successfully for {finding_id}")
            return jsonify({"status": "applied"})
        else:
            logger.warning(f"Patch application failed for {finding_id}")
            return jsonify({"error": "Patch application failed"}), 500
    except Exception as e:
        logger.error(f"Patch application error for {finding_id}: {e}")
        return jsonify({"error": "Internal error applying patch"}), 500
