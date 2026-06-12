import json
import os
from pathlib import Path

from flask import Blueprint, jsonify

from devsecops_radar.core.auth import require_any_auth

topology_bp = Blueprint("topology", __name__)

_ALLOWED_DATA_DIR = Path.cwd().resolve()
TOPOLOGY_FILE = os.environ.get("TOPOLOGY_FILE", "topology.json")

def _safe_data_path(filename: str) -> Path | None:
    file_path = (_ALLOWED_DATA_DIR / filename).resolve()
    try:
        if file_path.is_relative_to(_ALLOWED_DATA_DIR):
            return file_path
    except ValueError:
        pass
    return None

@topology_bp.route("/topology")
@require_any_auth
def api_topology():
    safe_path = _safe_data_path(TOPOLOGY_FILE)
    if safe_path and safe_path.exists():
        if safe_path.stat().st_size > 10 * 1024 * 1024:
            return jsonify({"error": "Topology file too large"}), 413
        with open(safe_path, encoding="utf-8") as f:
            return jsonify(json.load(f))
    return jsonify({})