from flask import Blueprint, jsonify, render_template_string, request
import json
import os
from devsecops_radar.core.database import get_all_scans, get_findings_paginated
from devsecops_radar.core.rag import rag_search

dashboard_bp = Blueprint('dashboard', __name__)

FINDINGS_FILE = os.environ.get('FINDINGS_FILE', 'findings.json')

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pipeline Sentinel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { padding-bottom: 2rem; background: #0f172a; color: #e2e8f0; }
        .severity-row.severity-critical { border-left: 4px solid #dc3545; }
        .severity-row.severity-high { border-left: 4px solid #fd7e14; }
        .severity-row.severity-medium { border-left: 4px solid #0dcaf0; }
        .severity-row.severity-low { border-left: 4px solid #0d6efd; }
        .navbar { box-shadow: 0 2px 10px rgba(0,0,0,0.3); }
        .card { border: none; border-radius: 10px; background: #1e293b; color: #e2e8f0; }
        .card:hover { transform: translateY(-2px); transition: transform 0.2s; }
        .table { border-radius: 10px; overflow: hidden; }
        .badge { font-size: 0.8rem; padding: 0.4em 0.6em; }
        code { color: #38bdf8; }
        #attack-graph, #topology-graph { background: #1e293b; border-radius: 10px; }
        #attack-detail { background: #1e293b; border-radius: 10px; padding: 1rem; margin-top: 1rem; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
    <script src="https://d3js.org/d3.v7.min.js"></script>
</head>
<body>
    <nav class="navbar navbar-dark border-bottom border-secondary mb-4" style="background:#1e293b;">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">🛡️ Pipeline Sentinel</span>
            <span class="text-muted">v0.3.2</span>
        </div>
    </nav>

    <div class="container">
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">Severity Breakdown</h5>
                        <canvas id="severityChart" width="100" height="100"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-8">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">Trend Over Time</h5>
                        <canvas id="trendChart" width="300" height="100"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4" id="pipeline-summary-row">
            <div class="col-12">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">Pipeline Security (Poutine & Zizmor)</h5>
                        <div class="d-flex gap-3">
                            <div class="p-2 bg-dark rounded"><span id="pipeline-critical" class="fs-4 text-danger">0</span> Critical</div>
                            <div class="p-2 bg-dark rounded"><span id="pipeline-high" class="fs-4 text-warning">0</span> High</div>
                            <div class="p-2 bg-dark rounded"><span id="pipeline-medium" class="fs-4 text-info">0</span> Medium</div>
                            <div class="p-2 bg-dark rounded"><span id="pipeline-low" class="fs-4 text-primary">0</span> Low</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4" id="attack-path-row">
            <div class="col-12">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">Attack Paths (AI-Generated)</h5>
                        <div id="attack-graph" style="width:100%; height:400px;"></div>
                        <div id="attack-detail" style="display:none;"></div>
                        <div id="attack-error" class="text-warning mt-2" style="display:none;"></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4" id="topology-row" style="display:none;">
            <div class="col-12">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">Topology (Assets & Connections)</h5>
                        <div id="topology-graph" style="width:100%; height:400px;"></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4" id="summary-row">
            <div class="col-12">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">AI Executive Summary</h5>
                        <div id="exec-summary" class="text-muted">No AI analysis available. Run with --analyze to generate one.</div>
                        <div id="risk-score" class="mt-2"></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-12">
                <div class="card shadow">
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
                                    <option value="Gitleaks">Gitleaks</option>
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

        <div class="card shadow">
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
                    <tbody id="tableBody"></tbody>
                </table>
            </div>
        </div>

        <footer class="text-center text-muted py-3 mt-5 border-top border-secondary">
            <small>🛡️ <strong>Pipeline Sentinel</strong> · crafted by <a href="https://github.com/Mehrdoost" class="text-decoration-none text-info" target="_blank">Mehrdoost</a> · <a href="https://github.com/Mehrdoost/devsecops-radar" class="text-decoration-none text-info" target="_blank">View on GitHub</a></small>
        </footer>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const API_KEY = "{{ api_key }}";
        function getHeaders() {
            if (API_KEY && API_KEY !== 'disabled') {
                return { 'X-API-Key': API_KEY };
            }
            return {};
        }

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

        fetch('/api/findings', { headers: getHeaders() })
            .then(res => res.json())
            .then(data => {
                allFindings = data.items;
                renderTable(allFindings);
                const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
                allFindings.forEach(f => {
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
                const pipeline = allFindings.filter(f => f.tool === 'Poutine' || f.tool === 'Zizmor');
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

        fetch('/api/history', { headers: getHeaders() })
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

        fetch('/api/attack-paths', { headers: getHeaders() })
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
                    .on('click', (event, d) => {
                        const detail = document.getElementById('attack-detail');
                        detail.innerHTML = `<strong>${d.id}</strong><br>Severity: ${d.severity}<br>${d.title}`;
                        detail.style.display = 'block';
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

        fetch('/api/summary', { headers: getHeaders() })
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

        fetch('/api/topology', { headers: getHeaders() })
            .then(res => res.json())
            .then(topo => {
                if (!topo || !topo.servers || topo.servers.length === 0) return;
                document.getElementById('topology-row').style.display = 'block';
                const nodes = topo.servers.map(s => ({ id: s.name, group: s.ip }));
                const links = topo.connections.map(c => ({ source: c.source, target: c.target, label: c.protocol }));
                const container = document.getElementById('topology-graph');
                const width = container.clientWidth;
                const height = container.clientHeight;
                const svg = d3.select('#topology-graph')
                    .append('svg')
                    .attr('width', width)
                    .attr('height', height);
                const simulation = d3.forceSimulation(nodes)
                    .force('link', d3.forceLink(links).id(d => d.id).distance(80))
                    .force('charge', d3.forceManyBody().strength(-300))
                    .force('center', d3.forceCenter(width / 2, height / 2));
                const link = svg.append('g')
                    .selectAll('line')
                    .data(links)
                    .enter().append('line')
                    .attr('stroke', '#6c757d')
                    .attr('stroke-width', 2);
                const node = svg.append('g')
                    .selectAll('circle')
                    .data(nodes)
                    .enter().append('circle')
                    .attr('r', 12)
                    .attr('fill', '#0d6efd')
                    .call(d3.drag()
                        .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
                        .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
                        .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));
                const label = svg.append('g')
                    .selectAll('text')
                    .data(nodes)
                    .enter().append('text')
                    .text(d => d.id)
                    .attr('font-size', '10px')
                    .attr('dx', 15)
                    .attr('dy', 4)
                    .attr('fill', 'white');
                simulation.on('tick', () => {
                    link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
                    node.attr('cx', d => d.x).attr('cy', d => d.y);
                    label.attr('x', d => d.x).attr('y', d => d.y);
                });
            });
    </script>
</body>
</html>
"""

def load_findings():
    if not os.path.exists(FINDINGS_FILE):
        return []
    with open(FINDINGS_FILE, 'r') as f:
        return json.load(f)

@dashboard_bp.route('/')
def index():
    findings = load_findings()
    return render_template_string(
        DASHBOARD_HTML,
        findings=findings,
        api_key=os.environ.get("PIPELINE_API_KEY", "disabled")
    )

@dashboard_bp.route('/api/findings')
def api_findings():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    return jsonify(get_findings_paginated(page, per_page))

@dashboard_bp.route('/api/history')
def api_history():
    return jsonify(get_all_scans())

@dashboard_bp.route('/api/rag')
def api_rag():
    q = request.args.get('q', '')
    if not q:
        return jsonify([])
    return jsonify(rag_search(q))