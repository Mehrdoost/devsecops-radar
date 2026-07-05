# devsecops_radar/web/attack_paths/routes.py
"""
Attack paths API – powered by database and optional AI analysis.
Supports optional ?scan_id= to retrieve historical attack graphs.
"""

from __future__ import annotations

import json
from html import escape as html_escape
from typing import Any

from flask import Blueprint, Response, jsonify, request
from loguru import logger

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.database import SessionLocal
from devsecops_radar.core.models import Finding, Scan

attack_paths_bp = Blueprint("attack_paths", __name__)


def _get_latest_ai_analysis() -> dict[str, Any] | None:
    """Retrieve the most recent AI analysis from the database, if any."""
    session = SessionLocal()
    try:
        scan = session.query(Scan).order_by(Scan.id.desc()).first()
        if not scan or not scan.ai_summary_json:
            return None
        try:
            return json.loads(str(scan.ai_summary_json))
        except (json.JSONDecodeError, TypeError):
            logger.error("Corrupted AI summary JSON in database.")
            return None
    finally:
        session.close()


def _get_ai_analysis_by_scan_id(scan_id: int) -> dict[str, Any] | None:
    """Retrieve AI analysis for a specific scan."""
    session = SessionLocal()
    try:
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or not scan.ai_summary_json:
            return None
        try:
            return json.loads(str(scan.ai_summary_json))
        except (json.JSONDecodeError, TypeError):
            logger.error("Corrupted AI summary JSON in database.")
            return None
    finally:
        session.close()


def _build_graph_from_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Build a deterministic attack graph based on shared targets.
    Used when no AI analysis is available.  Expects plain dicts, not ORM objects.
    """
    nodes: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    node_ids: set[str] = set()

    for f in findings:
        fid = str(f.get("id", ""))
        if fid not in node_ids:
            node_ids.add(fid)
            severity = str(f.get("severity", "UNKNOWN")).upper()
            color_map: dict[str, str] = {
                "CRITICAL": "#DC3545",
                "HIGH": "#FD7E14",
                "MEDIUM": "#FFC107",
                "LOW": "#0D6EFD",
            }
            nodes.append({
                "id": html_escape(str(f.get("id") or "UNKNOWN")),
                "label": html_escape(f"{f.get('tool', '')}: {f.get('id', 'N/A')}"),
                "title": html_escape(str(f.get("title") or "")),
                "severity": severity,
                "target": html_escape(str(f.get("target") or "")),
                "color": color_map.get(severity, "#6C757D"),
            })

    target_map: dict[str, list[str]] = {}
    for f in findings:
        target = str(f.get("target") or "unknown")
        fid = str(f.get("id", ""))
        target_map.setdefault(target, []).append(fid)

    for target, ids in target_map.items():  # noqa: B007
        if len(ids) > 1:
            for i in range(len(ids) - 1):
                links.append({
                    "source": html_escape(ids[i]),
                    "target": html_escape(ids[i + 1]),
                    "label": "shared target",
                })

    return {"nodes": nodes, "links": links}


@attack_paths_bp.route("/attack-paths")
@require_any_auth
def api_attack_paths() -> Response:
    # Check if a specific scan is requested
    scan_id = request.args.get("scan_id", type=int)

    # 1. Historical AI‑powered graph for a specific scan
    if scan_id is not None:
        ai_analysis = _get_ai_analysis_by_scan_id(scan_id)
        if ai_analysis is None:
            resp = jsonify({"error": "No AI analysis found for this scan."})
            resp.status_code = 404
            return resp

        attack_paths_raw = ai_analysis.get("attack_paths", [])
        all_involved: set[str] = set()
        for path in attack_paths_raw:
            for fid in path.get("involved_findings", []):
                if isinstance(fid, str):
                    all_involved.add(fid)

        findings_by_id: dict[str, dict[str, Any]] = {}
        if all_involved:
            session = SessionLocal()
            try:
                rows = session.query(Finding).filter(
                    Finding.rule_id.in_(list(all_involved))
                ).limit(500).all()
                for r in rows:
                    findings_by_id[str(r.rule_id)] = {
                        "severity": r.severity,
                        "title": r.title,
                    }
            finally:
                session.close()

        nodes: list[dict[str, Any]] = []
        links: list[dict[str, Any]] = []
        node_ids_set: set[str] = set()
        for path in attack_paths_raw:
            involved = path.get("involved_findings", [])
            for fid in involved:
                if fid not in node_ids_set:
                    finfo = findings_by_id.get(fid, {})
                    nodes.append({
                        "id": html_escape(fid),
                        "label": html_escape(fid),
                        "severity": html_escape(str(finfo.get("severity", "UNKNOWN"))),
                        "title": html_escape(str(finfo.get("title", "")[:50])),
                    })
                    node_ids_set.add(fid)
            for i in range(len(involved) - 1):
                links.append({
                    "source": html_escape(involved[i]),
                    "target": html_escape(involved[i + 1]),
                    "description": html_escape(str(path.get("description", ""))),
                })

        return jsonify({
            "attack_paths": attack_paths_raw,
            "nodes": nodes,
            "links": links,
        })

    # 2. Latest AI‑powered graph (default)
    ai_analysis = _get_latest_ai_analysis()
    if ai_analysis is not None:
        attack_paths_raw = ai_analysis.get("attack_paths", [])
        all_involved = set()
        for path in attack_paths_raw:
            for fid in path.get("involved_findings", []):
                if isinstance(fid, str):
                    all_involved.add(fid)

        findings_by_id = {}
        if all_involved:
            session = SessionLocal()
            try:
                rows = session.query(Finding).filter(
                    Finding.rule_id.in_(list(all_involved))
                ).limit(500).all()
                for r in rows:
                    findings_by_id[str(r.rule_id)] = {
                        "severity": r.severity,
                        "title": r.title,
                    }
            finally:
                session.close()

        nodes = []
        links = []
        node_ids_set = set()
        for path in attack_paths_raw:
            involved = path.get("involved_findings", [])
            for fid in involved:
                if fid not in node_ids_set:
                    finfo = findings_by_id.get(fid, {})
                    nodes.append({
                        "id": html_escape(fid),
                        "label": html_escape(fid),
                        "severity": html_escape(str(finfo.get("severity", "UNKNOWN"))),
                        "title": html_escape(str(finfo.get("title", "")[:50])),
                    })
                    node_ids_set.add(fid)
            for i in range(len(involved) - 1):
                links.append({
                    "source": html_escape(involved[i]),
                    "target": html_escape(involved[i + 1]),
                    "description": html_escape(str(path.get("description", ""))),
                })

        return jsonify({
            "attack_paths": attack_paths_raw,
            "nodes": nodes,
            "links": links,
        })

    # 3. Fallback: simple graph from all findings
    session = SessionLocal()
    try:
        findings_orm = session.query(Finding).limit(200).all()
        findings_dicts = [
            {
                "id": f.rule_id,
                "tool": f.tool,
                "severity": f.severity,
                "target": f.target,
                "title": f.title,
            }
            for f in findings_orm
        ]
    finally:
        session.close()

    graph = _build_graph_from_findings(findings_dicts)
    return jsonify({
        "attack_paths": [],
        "nodes": graph["nodes"],
        "links": graph["links"],
    })
