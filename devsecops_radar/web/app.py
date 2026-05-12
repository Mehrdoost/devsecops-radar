from flask import Flask, render_template, jsonify
import json
import os
from devsecops_radar.core.database import get_all_scans

app = Flask(__name__)

FINDINGS_FILE = os.environ.get('FINDINGS_FILE', 'findings.json')

def load_findings():
    if not os.path.exists(FINDINGS_FILE):
        return []
    with open(FINDINGS_FILE) as f:
        return json.load(f)

@app.route('/')
def index():
    findings = load_findings()
    return render_template('index.html', findings=findings)

@app.route('/api/findings')
def api_findings():
    return jsonify(load_findings())

@app.route('/api/history')
def api_history():
    return jsonify(get_all_scans())

def start_server(host='0.0.0.0', port=8080):
    app.run(host=host, port=port, debug=True)

if __name__ == '__main__':
    start_server()