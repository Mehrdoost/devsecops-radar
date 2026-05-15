from flask import Flask, jsonify, render_template_string
import json
import os
from devsecops_radar.core.database import get_all_scans

app = Flask(__name__)

FINDINGS_FILE = os.environ.get('FINDINGS_FILE', 'findings.json')
AI_SUMMARY_FILE = os.environ.get('AI_SUMMARY_FILE', 'findings_ai_summary.json')

# ------------------------------------------
# Embedded HTML template – professional dashboard
# ------------------------------------------
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
        #attack-graph { background: #1e293b; border-radius: 10px; }
        .pipeline-badge { background: #6f42c1; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
    <script src="https://d3js.org/d3.v7.min.js"></script>
</head>
<body class="bg-dark text-light">
    <nav class="navbar navbar-dark border-bottom border-secondary mb-4">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">🛡️ Pipeline Sentinel</span>
        </div>
    </nav>
    <div class="container">
        <!-- Charts Row -->
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

        <!-- Pipeline Security Summary (Poutine + Zizmor) -->
        <div class="row mb-4" id="pipeline-summary-row">
            <div class="col-12">
                <div class="card bg-secondary text-white shadow">
                    <div class="card-body">
                        <h5 class="card-title">Pipeline Security (Poutine & Zizmor)</h5>
                        <div id="pipeline-summary" class="d-flex gap-3">
                            <div class="p-2 bg-dark rounded">
                                <span id="pipeline-critical" class="fs-4 text-danger">0</span> Critical
                            </div>
                            <div class="p-2 bg-dark rounded">
                                <span id="pipeline-high" class="fs-4 text-warning">0</span> High
                            </div>
                            <div class="p-2 bg-dark rounded">
                                <span id="pipeline-medium" class="fs-4 text-info">0</span> Medium
                            </div>
                            <div class="p-2 bg-dark rounded">
                                <span id="pipeline-low" class="fs-4 text-primary">0</span> Low
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Attack Path Visualization -->
        <div class="row mb-4" id="attack-path-row">
            <div class="col-12">
                <div class="card bg-secondary text-white shadow">
                    <div class="card-body">
                        <h5 class="card-title">Attack Paths (AI-Generated)</h5>
                        <div id="attack-graph" style="width:100%; height:400px;"></div>
                        <div id="attack-error" class="text-warning mt-2" style="display:none;"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Management Report Card -->
        <div class="row mb-4" id="summary-row">
            <div class="col-12">
                <div class="card bg-secondary text-white shadow">
                    <div class="card-body">
                        <h5 class="card-title">AI Executive Summary</h5>
                        <div id="exec-summary" class="text-muted">No AI analysis available. Run with --analyze to generate one.</div>
                        <div id="risk-score" class="mt-2"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Filters Row -->
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

        <!-- Findings Table -->
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

        // Fetch findings for table and donut chart
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

                // Pipeline-specific stats (Poutine + Zizmor)
                const pipeline = data.filter(f => f.tool === 'Poutine' || f.tool === 'Zizmor');
                const pCounts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
                pipeline.forEach(f => {
                    const sev = f.severity.toUpperCase();
                    pCounts[sev] = (pCounts[sev] || 0) + 1;
                });
                document.getElementById('pipeline-critical').textContent = pCounts.CRITICAL;
                document.getElementById('pipeline-high').textContent = pCounts.HIGH;
                document.getElementById('pipeline-medium').textContent = pCounts.MEDIUM;
                document.getElementById('pipeline-low').textContent = pCounts.LOW;

                document.getElementById('searchInput').addEventListener('input', applyFilters);
                document.getElementById('toolFilter').addEventListener('change', applyFilters);
                document.getElementById('severityFilter').addEventListener('change', applyFilters);
            });

        // Fetch history for trend chart
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

        // Attack Path Graph
        fetch('/api/attack-paths')
            .then(res => res.json())
            .then(data => {
                if (data.error) {
                    document.getElementById('attack-error').style.display = 'block';
                    document.getElementById('attack-error').textContent = data.error;
                    return;
                }
                if (!data.nodes || data.nodes.length === 0) return;
                const container = document.getElementById('attack-graph');
                const width = container.clientWidth;
                const height = container.clientHeight;
                const svg = d3.select('#attack-graph')
                    .append('svg')
                    .attr('width', width)
                    .attr('height', height);

                const simulation = d3.forceSimulation(data.nodes)
                    .force('link', d3.forceLink(data.links).id(d => d.id).distance(100))
                    .force('charge', d3.forceManyBody().strength(-400))
                    .force('center', d3.forceCenter(width / 2, height / 2));

                const link = svg.append('g')
                    .selectAll('line')
                    .data(data.links)
                    .enter().append('line')
                    .attr('stroke', '#999')
                    .attr('stroke-opacity', 0.6);

                const node = svg.append('g')
                    .selectAll('circle')
                    .data(data.nodes)
                    .enter().append('circle')
                    .attr('r', 8)
                    .attr('fill', d => {
                        switch(d.severity) {
                            case 'CRITICAL': return '#dc3545';
                            case 'HIGH': return '#fd7e14';
                            case 'MEDIUM': return '#0dcaf0';
                            case 'LOW': return '#0d6efd';
                            default: return '#6c757d';
                        }
                    })
                    .call(d3.drag()
                        .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
                        .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
                        .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));

                const label = svg.append('g')
                    .selectAll('text')
                    .data(data.nodes)
                    .enter().append('text')
                    .text(d => d.id)
                    .attr('font-size', '10px')
                    .attr('dx', 12)
                    .attr('dy', 4)
                    .attr('fill', 'white');

                simulation.on('tick', () => {
                    link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
                    node.attr('cx', d => d.x).attr('cy', d => d.y);
                    label.attr('x', d => d.x).attr('y', d => d.y);
                });
            })
            .catch(err => {
                document.getElementById('attack-error').style.display = 'block';
                document.getElementById('attack-error').textContent = 'Could not load attack graph: ' + err.message;
            });

        // AI Summary
        fetch('/api/summary')
            .then(res => res.json())
            .then(data => {
                if (data.executive_summary) {
                    document.getElementById('exec-summary').textContent = data.executive_summary;
                    if (data.risk_score) {
                        document.getElementById('risk-score').innerHTML = `
                            <span class="badge bg-${data.risk_score > 70 ? 'danger' : data.risk_score > 40 ? 'warning text-dark' : 'success'} fs-6">
                                Risk Score: ${data.risk_score}/100
                            </span>`;
                    }
                }
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

def load_ai_summary():
    if not os.path.exists(AI_SUMMARY_FILE):
        return {}
    with open(AI_SUMMARY_FILE) as f:
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

@app.route('/api/summary')
def api_summary():
    return jsonify(load_ai_summary())

@app.route('/api/attack-paths')
def api_attack_paths():
    """Return LLM-generated attack paths for the latest scan, gracefully handle missing Ollama."""
    findings = load_findings()
    if not findings:
        return jsonify({"attack_paths": [], "nodes": [], "links": []})
    try:
        from devsecops_radar.core.analyzer import OllamaAnalyzer
        analyzer = OllamaAnalyzer()
        analysis = analyzer.analyze(findings)
        attack_paths = analysis.get("attack_paths", [])
        
        nodes = []
        links = []
        node_ids = set()
        
        for path in attack_paths:
            involved = path.get("involved_findings", [])
            for fid in involved:
                if fid not in node_ids:
                    finding = next((f for f in findings if f.get("id") == fid), None)
                    nodes.append({
                        "id": fid,
                        "label": fid,
                        "severity": finding.get("severity", "UNKNOWN") if finding else "UNKNOWN",
                        "title": finding.get("title", "")[:50] if finding else ""
                    })
                    node_ids.add(fid)
            for i in range(len(involved) - 1):
                links.append({
                    "source": involved[i],
                    "target": involved[i+1],
                    "description": path.get("description", "")
                })
        
        return jsonify({"attack_paths": attack_paths, "nodes": nodes, "links": links})
    except Exception as e:
        return jsonify({"error": f"AI analysis unavailable: {str(e)}. Run with --analyze to generate.", "attack_paths": [], "nodes": [], "links": []})

@app.route('/api/scans')
def api_scans():
    return jsonify(get_all_scans())

def start_server(host='0.0.0.0', port=8080):
    app.run(host=host, port=port, debug=True)

if __name__ == '__main__':
    start_server()