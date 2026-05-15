from flask import Blueprint, jsonify
import json
import os

topology_bp = Blueprint('topology', __name__)

@topology_bp.route('/api/topology')
def api_topology():
    topo_file = os.environ.get("TOPOLOGY_FILE", "topology.json")
    if os.path.exists(topo_file):
        with open(topo_file) as f:
            return jsonify(json.load(f))
    return jsonify({})