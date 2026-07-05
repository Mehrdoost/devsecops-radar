# devsecops_radar/web/topology/routes.py
"""
Infrastructure topology API with in‑memory caching.
Reads from a JSON file; a future version should persist topology
in the database for consistency with the CLI and valuation.
"""

from __future__ import annotations

import json
import os
import time
from html import escape as html_escape
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify
from loguru import logger

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.path_security import resolve_safe_path, safe_read_open
from devsecops_radar.core.reporting import redact_sensitive

topology_bp = Blueprint("topology", __name__)

_ALLOWED_DATA_DIR = Path.cwd().resolve()
TOPOLOGY_FILE = os.environ.get("TOPOLOGY_FILE", "topology.json")

# Simple in‑memory cache
_cache: dict[str, Any] | None = None
_cache_time: float = 0.0
_CACHE_TTL = 30  # seconds


def _sanitize_asset(asset: dict) -> dict:
    """Return a copy of *asset* with all string values HTML‑escaped and redacted."""
    clean: dict = {}
    for key, value in asset.items():
        if isinstance(value, str):
            clean[key] = html_escape(redact_sensitive(value))
        elif isinstance(value, dict):
            clean[key] = _sanitize_asset(value)
        elif isinstance(value, list):
            clean[key] = [
                _sanitize_asset(item) if isinstance(item, dict)
                else html_escape(redact_sensitive(item)) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            clean[key] = value
    return clean


@topology_bp.route("/topology")
@require_any_auth
def api_topology():
    global _cache, _cache_time

    # Return cached data if still fresh
    now = time.time()
    if _cache is not None and (now - _cache_time) < _CACHE_TTL:
        return jsonify(_cache)

    # Validate the topology file path
    try:
        safe_path = resolve_safe_path(TOPOLOGY_FILE, _ALLOWED_DATA_DIR)
    except ValueError:
        return jsonify({"error": "Topology path not allowed"}), 403

    try:
        with safe_read_open(safe_path, base_dir=_ALLOWED_DATA_DIR) as f:
            # Use fstat on the open file descriptor to avoid TOCTOU
            try:
                stat = os.fstat(f.fileno())
                if stat.st_size > 10 * 1024 * 1024:
                    return jsonify({"error": "Topology file too large"}), 413
            except OSError as e:
                logger.error(f"Cannot stat topology file: {e}")
                return jsonify({})

            topology = json.load(f)
    except (FileNotFoundError, PermissionError, OSError, json.JSONDecodeError) as e:
        logger.error(f"Cannot read topology file: {e}")
        return jsonify({})

    # Sanitize all asset strings to prevent XSS and information leaks
    if "assets" in topology:
        topology["assets"] = [_sanitize_asset(a) for a in topology["assets"]]

    # Update cache
    _cache = topology
    _cache_time = now

    return jsonify(topology)
