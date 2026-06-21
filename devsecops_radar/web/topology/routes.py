# devsecops_radar/web/topology/routes.py
import json
import os
from pathlib import Path

from flask import Blueprint, jsonify

from devsecops_radar.core.auth import require_any_auth
from devsecops_radar.core.path_security import safe_read_open

topology_bp = Blueprint("topology", __name__)

_ALLOWED_DATA_DIR = Path.cwd().resolve()
TOPOLOGY_FILE = os.environ.get("TOPOLOGY_FILE", "topology.json")


@topology_bp.route("/topology")
@require_any_auth
def api_topology():
    try:
        with safe_read_open(TOPOLOGY_FILE, base_dir=_ALLOWED_DATA_DIR) as f:
            try:
                stat = os.fstat(f.fileno())
                if stat.st_size > 10 * 1024 * 1024:
                    return jsonify({"error": "Topology file too large"}), 413
            except OSError:
                return jsonify({"error": "Cannot read topology file"}), 500
            return jsonify(json.load(f))
    except (ValueError, FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
        return jsonify({})
