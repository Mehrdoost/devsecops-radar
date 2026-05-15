from flask import Flask, jsonify, render_template_string
import json
import os
from devsecops_radar.core.database import get_all_scans

app = Flask(__name__)

FINDINGS_FILE = os.environ.get('FINDINGS_FILE', 'findings.json')

# Embedded HTML template – no external files needed
DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevSecOps Radar</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { padding-bottom: 2rem; }
        .severity-row.severity-critical { border-left: 4px solid #dc3545; }
        .severity-row.severity-high { border-left: 4px solid #fd7e14; }
        .severity-row.severity-medium { border-left: 4px solid #0dcaf0; }
        .severity-row.severity-low { border-left: 4px solid #0d6efd; }
        .navbar { box-shadow: 0 2px 10px rgba(0,0,0,0.3); }
        .card { border: none; border-radius: 10px; transition: transform 0.2s; }
        .card:hover { transform: translateY(-2px); }
        .table { border-radius: 10px; overflow: hidden; }
        .badge { font-size: 0.8rem; padding: 0.4em 0.6em; }
        code { color: #38bdf8; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
</head>
<body class="bg-dark text-light">
    <nav class="navbar navbar-dark border-bottom border-secondary mb-4">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">🛡️ DevSecOps Radar</span>
        </div>
    </nav>
    <div class="container">
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="card bg-secondary text-white shadow">
                    <div class="card-body">
                        <h5 class="card-title">Severity Breakdown</h5>
                        <canvas id="severityChart" width="100" height="100"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-8">
                <div class="card bg-secondary text-white shadow">
                    <div class="card-body">
                        <h5 class="card-title">Trend Over Time</h5>
                        <canvas id="trendChart" width="300" height="100"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-12">
                <div class="card bg-secondary text-white shadow">
                    <div class="card-body">
                        <h5 class="card-title">Filters</h5>
                        <div class="row g-2">
                            <div class="col">
                                <input type="text" id="searchInput" class="form-control" placeholder="Search...">
                            </div>
                            <div class="col">
                                <select id="toolFilter" class="form-select">
                                    <option value="">All Tools</option>
                                    <option value="Trivy">Trivy</option>
                                    <option value="Semgrep">Semgrep</option>
                                    <option value="Poutine">Poutine</option>
                                    <option value="Zizmor">Zizmor</option>
                                </select>
                            </div>
                            <div class="col">
                                <select id="severityFilter" class="form-select">
                                    <option value="">All Severities</option>
                                    <option value="CRITICAL">CRITICAL</option>
                                    <option value="HIGH">HIGH</option>
                                    <option value="MEDIUM">MEDIUM</option>
                                    <option value="LOW">LOW</option>
                                </select>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card bg-secondary text-white shadow">
            <div class="card-body">
                <table class="table table-dark table-striped table-hover" id="findings-table">
                    <thead>
                        <tr>
                            <th>Tool</th>
                            <th>ID</th>
                            <th>Severity</th>
                            <th>Target</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody id="tableBody">
                    </tbody>
                </table>
            </div>
        </div>

        <footer class="text-center text-muted py-3 mt-5 border-top border-secondary">
            <small>🛡️ <strong>Pipeline Sentinel</strong> · crafted by <a href="https://github.com/Mehrdoost" class="text-decoration-none text-info" target="_blank">Mehrdoost</a> · <a href="https://github.com/Mehrdoost/devsecops-radar" class="text-decoration-none text-info" target="_blank">View on GitHub</a></small>
        </footer>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // ---------- Inline dashboard JS ----------
        let allFindings = [];

        function renderTable(data) {
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';
            data.forEach(f => {
                const row = document.createElement('tr');
                row.className = `severity-row severity-${f.severity.toLowerCase()}`;
                row.innerHTML = `
                    <td>${f.tool}</td>
                    <td><code>${f.id}</code></td>
                    <td><span class="badge bg-${getSeverityColor(f.severity)}">${f.severity}</span></td>
                    <td>${f.target}</td>
                    <td>${f.description && f.description.length > 80 ? f.description.substring(0,80)+'...' : f.description}</td>
                `;
                tbody.appendChild(row);
            });
        }

        function getSeverityColor(severity) {
            switch(severity.toUpperCase()) {
                case 'CRITICAL': return 'danger';
                case 'HIGH': return 'warning text-dark';
                case 'MEDIUM': return 'info text-dark';
                case 'LOW': return 'primary';
                default: return 'secondary';
            }
        }

        function applyFilters() {
            const search = document.getElementById('searchInput').value.toLowerCase();
            const tool = document.getElementById('toolFilter').value;
            const severity = document.getElementById('severityFilter').value;
            const filtered = allFindings.filter(f => 
                (f.id.toLowerCase().includes(search) || (f.description && f.description.toLowerCase().includes(search))) &&
                (tool === '' || f.tool === tool) &&
                (severity === '' || f.severity === severity)
            );
            renderTable(filtered);
        }

        fetch('/api/findings')
            .then(res => res.json())
            .then(data => {
                allFindings = data;
                renderTable(data);

                const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
                data.forEach(f => {
                    const sev = f.severity.toUpperCase();
                    counts[sev] = (counts[sev] || 0) + 1;
                });
                new Chart(document.getElementById('severityChart'), {
                    type: 'doughnut',
                    data: {
                        labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        datasets: [{
                            data: [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW],
                            backgroundColor: ['#dc3545','#fd7e14','#0dcaf0','#0d6efd']
                        }]
                    },
                    options: { plugins: { legend: { labels: { color: 'white' } } } }
                });

                document.getElementById('searchInput').addEventListener('input', applyFilters);
                document.getElementById('toolFilter').addEventListener('change', applyFilters);
                document.getElementById('severityFilter').addEventListener('change', applyFilters);
            });

        fetch('/api/history')
            .then(res => res.json())
            .then(scans => {
                if (!scans.length) return;
                const labels = scans.map(s => s.timestamp.substring(0,10));
                new Chart(document.getElementById('trendChart'), {
                    type: 'line',
                    data: {
                        labels,
                        datasets: [
                            { label: 'CRITICAL', data: scans.map(s => s.critical), borderColor: '#dc3545', fill: false },
                            { label: 'HIGH', data: scans.map(s => s.high), borderColor: '#fd7e14', fill: false },
                            { label: 'MEDIUM', data: scans.map(s => s.medium), borderColor: '#0dcaf0', fill: false },
                            { label: 'LOW', data: scans.map(s => s.low), borderColor: '#0d6efd', fill: false }
                        ]
                    },
                    options: {
                        scales: { y: { beginAtZero: true, ticks: { color: 'white' } }, x: { ticks: { color: 'white' } } },
                        plugins: { legend: { labels: { color: 'white' } } }
                    }
                });
            });
    </script>
</body>
</html>
"""

def load_findings():
    if not os.path.exists(FINDINGS_FILE):
        return []
    with open(FINDINGS_FILE) as f:
        return json.load(f)

@app.route('/')
def index():
    findings = load_findings()
    return render_template_string(DASHBOARD_HTML, findings=findings)

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