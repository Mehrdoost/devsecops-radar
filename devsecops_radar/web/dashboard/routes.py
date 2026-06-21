# devsecops_radar/web/dashboard/routes.py
import asyncio
import io
import json
import os
import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from html import escape as html_escape
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file
from loguru import logger

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.database import db_session, get_findings_paginated
from devsecops_radar.core.models import Scan
from devsecops_radar.core.path_security import safe_read_open
from devsecops_radar.core.rag import rag_search
from devsecops_radar.core.reporting import generate_pdf_report, redact_sensitive
from devsecops_radar.web.sentry.routes import get_live_snapshot  # <-- new import

dashboard_bp = Blueprint("dashboard", __name__)

_ALLOWED_DATA_DIR = Path.cwd().resolve()
FINDINGS_FILE = os.environ.get("FINDINGS_FILE", "findings.json")
AI_SUMMARY_FILE = os.environ.get("AI_SUMMARY_FILE", "findings_ai_summary.json")


def load_findings() -> list[dict]:
    """Load findings from the validated JSON file (TOCTOU‑safe)."""
    try:
        with safe_read_open(FINDINGS_FILE, base_dir=_ALLOWED_DATA_DIR) as f:
            return json.load(f)
    except (ValueError, FileNotFoundError, PermissionError, OSError, json.JSONDecodeError) as e:
        logger.error(f"Failed to load findings: {e}")
        return []


def load_ai_summary() -> dict:
    """Load AI summary securely."""
    try:
        with safe_read_open(AI_SUMMARY_FILE, base_dir=_ALLOWED_DATA_DIR) as f:
            return json.load(f)
    except (ValueError, FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
        return {}


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
    return jsonify(get_findings_paginated(page, per_page))


@dashboard_bp.route("/api/history")
@require_any_auth
def api_history():
    session = db_session()
    try:
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
    finally:
        pass  # scoped session handled by teardown


@dashboard_bp.route("/api/scanner-status")
@require_any_auth
def scanner_status():
    scanners = ["trivy", "semgrep", "poutine", "zizmor", "gitleaks"]
    status = {name: shutil.which(name) is not None for name in scanners}
    return jsonify(status)


@dashboard_bp.route("/api/live-feed")
@require_any_auth
def live_feed():
    """Expose the latest live findings from the sentry buffer (TTL‑pruned)."""
    return jsonify(get_live_snapshot())


@dashboard_bp.route("/api/policy-status")
@require_any_auth
def policy_status():
    policy_path = Path("policy.json")
    if not policy_path.exists():
        return jsonify({"status": "no_policy"})
    try:
        with safe_read_open(policy_path, base_dir=_ALLOWED_DATA_DIR) as f:
            policy = json.load(f)
        max_crit = policy.get("max_critical")
        if max_crit is None:
            return jsonify({"status": "invalid_policy"})
        findings = load_findings()
        crit_count = sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL")
        return jsonify({
            "max_critical": max_crit,
            "current_critical": crit_count,
            "violated": crit_count > max_crit,
        })
    except (ValueError, FileNotFoundError, json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read policy.json: {e}")
        return jsonify({"status": "error"})


@dashboard_bp.route("/api/notify-jira", methods=["POST"])
@require_any_auth
def notify_jira_endpoint():
    data = request.get_json(force=True)
    finding_ids = data.get("finding_ids", [])
    if not isinstance(finding_ids, list):
        return jsonify({"error": "finding_ids must be a list"}), 400
    findings = [f for f in load_findings() if f.get("id") in finding_ids]
    if not findings:
        return jsonify({"error": "No matching findings provided"}), 400

    jira_url = os.environ.get("JIRA_URL")
    jira_token = os.environ.get("JIRA_TOKEN")
    if not jira_url or not jira_token:
        return jsonify({"error": "JIRA_URL and JIRA_TOKEN must be set"}), 500

    from devsecops_radar.core.notifier import notify_jira
    try:
        asyncio.run(notify_jira(findings, jira_url, jira_token))
        return jsonify({"status": "sent"})
    except Exception as e:
        logger.error(f"Failed to send Jira notification: {e}")
        return jsonify({"error": "Jira notification failed"}), 500


@dashboard_bp.route("/api/notify-asana", methods=["POST"])
@require_any_auth
def notify_asana_endpoint():
    data = request.get_json(force=True)
    finding_ids = data.get("finding_ids", [])
    if not isinstance(finding_ids, list):
        return jsonify({"error": "finding_ids must be a list"}), 400
    findings = [f for f in load_findings() if f.get("id") in finding_ids]
    if not findings:
        return jsonify({"error": "No matching findings provided"}), 400

    asana_token = os.environ.get("ASANA_TOKEN")
    asana_workspace = os.environ.get("ASANA_WORKSPACE")
    if not asana_token or not asana_workspace:
        return jsonify({"error": "ASANA_TOKEN and ASANA_WORKSPACE must be set"}), 500

    from devsecops_radar.core.notifier import notify_asana
    try:
        asyncio.run(notify_asana(findings, asana_token, asana_workspace))
        return jsonify({"status": "sent"})
    except Exception as e:
        logger.error(f"Failed to send Asana notification: {e}")
        return jsonify({"error": "Asana notification failed"}), 500


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
    findings = load_findings()
    selected = [f for f in findings if f.get("id") in finding_ids]
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
                # Read script safely – confined to artifact.temp_dir (not /tmp)
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
    findings = load_findings()
    ai_summary = load_ai_summary()

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
        if ai_summary.get("executive_summary"):
            html_parts.append("<h2>Executive Summary</h2>")
            html_parts.append(f"<p>{html_escape(redact_sensitive(ai_summary['executive_summary']))}</p>")
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

    # PDF – generate to a unique temp file to avoid race conditions
    tmp_fd, tmp_path = tempfile.mkstemp(
        suffix=".pdf", prefix="sentinel_report_", dir=str(_ALLOWED_DATA_DIR)
    )
    os.close(tmp_fd)  # we'll let generate_pdf_report write to the path
    try:
        generate_pdf_report(findings, ai_summary, tmp_path, framework=framework, base_dir=_ALLOWED_DATA_DIR)
        return send_file(
            tmp_path,
            as_attachment=True,
            download_name="pipeline_sentinel_report.pdf",
        )
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
