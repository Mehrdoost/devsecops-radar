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
    <title>Pipeline Sentinel – Command Center</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0B0F19;
            --bg-secondary: #131A2E;
            --accent: #00E5FF;
            --accent-glow: rgba(0, 229, 255, 0.2);
            --text: #E2E8F0;
            --muted: #94A3B8;
            --danger: #FF4D6D;
            --warning: #FFB100;
            --info: #00B4D8;
            --success: #06D6A0;
        }
        body {
            background: var(--bg-primary);
            color: var(--text);
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 0;
            overflow-x: hidden;
        }
        .navbar {
            background: var(--bg-secondary) !important;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
        }
        .navbar-brand {
            font-weight: 700;
            letter-spacing: -0.5px;
            color: var(--accent) !important;
        }
        .card {
            background: var(--bg-secondary);
            border: 1px solid rgba(255,255,255,0.03);
            border-radius: 12px;
            transition: all 0.3s ease;
        }
        .card:hover {
            border-color: rgba(255,255,255,0.1);
            box-shadow: 0 0 30px rgba(0,229,255,0.1);
        }
        .stat-pill {
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            padding: 12px 20px;
            font-weight: 600;
        }
        .stat-pill span {
            font-size: 1.5rem;
        }
        .btn-accent {
            background: var(--accent);
            color: #000;
            border: none;
            font-weight: 600;
            border-radius: 8px;
            padding: 8px 16px;
            transition: all 0.2s;
        }
        .btn-accent:hover {
            background: #00C4E0;
            box-shadow: 0 0 20px var(--accent-glow);
        }
        .table {
            border-radius: 12px;
            overflow: hidden;
            background: var(--bg-secondary);
        }
        .table th {
            border-bottom: 2px solid rgba(255,255,255,0.1);
            color: var(--accent);
            font-weight: 600;
        }
        .table td, .table th {
            padding: 12px 16px;
            vertical-align: middle;
        }
        .severity-badge {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 6px;
        }
        #attack-graph, #topology-graph {
            background: var(--bg-secondary);
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.05);
        }
        .modal-content {
            background: var(--bg-secondary);
            color: var(--text);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
        }
        .modal-header {
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .modal-footer {
            border-top: 1px solid rgba(255,255,255,0.1);
        }
        .glow {
            box-shadow: 0 0 20px var(--accent-glow);
        }
        .simulate-btn {
            position: absolute;
            bottom: 20px;
            right: 20px;
            z-index: 10;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
    <script src="https://d3js.org/d3.v7.min.js"></script>
</head>
<body>
    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">🛡️ Pipeline Sentinel</span>
            <span class="text-muted" style="font-size:0.85rem">v0.4.0 · Command Center</span>
        </div>
    </nav>

    <div class="container py-4">
        <!-- Top Stats Row -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="card p-3 text-center">
                    <div class="stat-pill text-danger">
                        <span id="stat-critical">0</span><br>CRITICAL
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center">
                    <div class="stat-pill text-warning">
                        <span id="stat-high">0</span><br>HIGH
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center">
                    <div class="stat-pill text-info">
                        <span id="stat-medium">0</span><br>MEDIUM
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center">
                    <div class="stat-pill text-primary">
                        <span id="stat-low">0</span><br>LOW
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="row g-3 mb-4">
            <div class="col-md-6">
                <div class="card p-3">
                    <h5 class="card-title" style="color:var(--accent)">Severity Breakdown</h5>
                    <canvas id="severityChart" height="250"></canvas>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card p-3">
                    <h5 class="card-title" style="color:var(--accent)">Trend Over Time</h5>
                    <canvas id="trendChart" height="250"></canvas>
                </div>
            </div>
        </div>

        <!-- Attack Path & Topology -->
        <div class="row g-3 mb-4">
            <div class="col-12">
                <div class="card p-3">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <h5 class="card-title" style="color:var(--accent)">Attack Paths (AI‑Generated)</h5>
                        <button class="btn-accent" id="simulate-selected-btn" disabled>⚡ Simulate Selected</button>
                    </div>
                    <div id="attack-graph" style="width:100%; height:400px; position:relative;"></div>
                    <div id="attack-detail" class="mt-2" style="display:none;"></div>
                    <div id="attack-error" class="text-warning mt-2" style="display:none;"></div>
                </div>
            </div>
        </div>

        <!-- Findings Table with checkboxes for simulation -->
        <div class="card p-3 mb-4">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="card-title" style="color:var(--accent)">Findings</h5>
                <div>
                    <input type="text" id="searchInput" class="form-control" placeholder="Search..." style="background:var(--bg-primary); color:white; border:1px solid rgba(255,255,255,0.1);">
                </div>
            </div>
            <div class="table-responsive">
                <table class="table table-dark table-hover align-middle">
                    <thead>
                        <tr>
                            <th><input type="checkbox" id="select-all"></th>
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

        <!-- What‑If Simulation Modal -->
        <div class="modal fade" id="simulationModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-lg modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">⚡ Attack Simulation</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div id="simulation-result">
                            <div class="d-flex justify-content-center">
                                <div class="spinner-border text-accent" role="status"></div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>

        <footer class="text-center text-muted py-3 border-top border-secondary mt-4">
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
        let selectedFindings = new Set();

        function renderTable(data) {
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';
            data.forEach(f => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td><input type="checkbox" class="finding-checkbox" data-id="${f.id}" ${selectedFindings.has(f.id) ? 'checked' : ''}></td>
                    <td>${f.tool}</td>
                    <td><code style="color:var(--accent)">${f.id}</code></td>
                    <td><span class="badge bg-${getSeverityColor(f.severity)}">${f.severity}</span></td>
                    <td>${f.target}</td>
                    <td>${f.description && f.description.length > 80 ? f.description.substring(0,80)+'...' : f.description}</td>
                `;
                tbody.appendChild(row);
            });

            // Attach checkbox events
            document.querySelectorAll('.finding-checkbox').forEach(cb => {
                cb.addEventListener('change', function() {
                    const fid = this.dataset.id;
                    if (this.checked) selectedFindings.add(fid);
                    else selectedFindings.delete(fid);
                    document.getElementById('simulate-selected-btn').disabled = selectedFindings.size === 0;
                });
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
            const filtered = allFindings.filter(f =>
                (f.id.toLowerCase().includes(search) || (f.description && f.description.toLowerCase().includes(search)))
            );
            renderTable(filtered);
        }

        // Select all checkbox
        document.getElementById('select-all').addEventListener('change', function() {
            const checkboxes = document.querySelectorAll('.finding-checkbox');
            checkboxes.forEach(cb => {
                cb.checked = this.checked;
                if (this.checked) selectedFindings.add(cb.dataset.id);
                else selectedFindings.delete(cb.dataset.id);
            });
            document.getElementById('simulate-selected-btn').disabled = selectedFindings.size === 0;
        });

        // Fetch findings
        fetch('/api/findings', { headers: getHeaders() })
            .then(res => res.json())
            .then(data => {
                allFindings = data.items;
                renderTable(allFindings);
                updateStats(allFindings);
                document.getElementById('searchInput').addEventListener('input', applyFilters);
            });

        function updateStats(findings) {
            const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
            findings.forEach(f => {
                const sev = f.severity.toUpperCase();
                counts[sev] = (counts[sev] || 0) + 1;
            });
            document.getElementById('stat-critical').textContent = counts.CRITICAL;
            document.getElementById('stat-high').textContent = counts.HIGH;
            document.getElementById('stat-medium').textContent = counts.MEDIUM;
            document.getElementById('stat-low').textContent = counts.LOW;

            new Chart(document.getElementById('severityChart'), {
                type: 'doughnut',
                data: {
                    labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                    datasets: [{
                        data: [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW],
                        backgroundColor: ['#FF4D6D','#FFB100','#00B4D8','#06D6A0'],
                        borderColor: 'rgba(255,255,255,0.1)',
                        borderWidth: 2
                    }]
                },
                options: { plugins: { legend: { labels: { color: 'white' } } } }
            });
        }

        // Trend chart
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
                            { label: 'CRITICAL', data: scans.map(s => s.critical), borderColor: '#FF4D6D', tension: 0.3 },
                            { label: 'HIGH', data: scans.map(s => s.high), borderColor: '#FFB100', tension: 0.3 },
                            { label: 'MEDIUM', data: scans.map(s => s.medium), borderColor: '#00B4D8', tension: 0.3 },
                            { label: 'LOW', data: scans.map(s => s.low), borderColor: '#06D6A0', tension: 0.3 }
                        ]
                    },
                    options: {
                        scales: { y: { beginAtZero: true, ticks: { color: 'white' } }, x: { ticks: { color: 'white' } } },
                        plugins: { legend: { labels: { color: 'white' } } }
                    }
                });
            });

        // Attack Graph (same D3 code as before but with click simulation trigger)
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
                container.innerHTML = '';
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
                    .attr('stroke', '#94A3B8')
                    .attr('stroke-opacity', 0.6);
                const node = svg.append('g')
                    .selectAll('circle')
                    .data(data.nodes)
                    .enter().append('circle')
                    .attr('r', 10)
                    .attr('fill', d => {
                        switch(d.severity) {
                            case 'CRITICAL': return '#FF4D6D';
                            case 'HIGH': return '#FFB100';
                            case 'MEDIUM': return '#00B4D8';
                            case 'LOW': return '#06D6A0';
                            default: return '#6c757d';
                        }
                    })
                    .style('cursor', 'pointer')
                    .on('click', (event, d) => {
                        // Show detail and enable simulate for this node's findings
                        const detail = document.getElementById('attack-detail');
                        detail.innerHTML = `<strong>${d.id}</strong><br>Severity: ${d.severity}<br>${d.title}<br>
                            <button class="btn-accent mt-2" onclick="simulateAttack(['${d.id}'])">Simulate this attack</button>`;
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
            });

        // Simulate selected button
        document.getElementById('simulate-selected-btn').addEventListener('click', () => {
            const ids = Array.from(selectedFindings);
            if (ids.length === 0) return;
            simulateAttack(ids);
        });

        // Topology fetch (unchanged)
        fetch('/api/topology', { headers: getHeaders() })
            .then(res => res.json())
            .then(topo => {
                if (!topo || !topo.servers || topo.servers.length === 0) return;
                document.getElementById('topology-row')?.style?.display = 'block';
                const nodes = topo.servers.map(s => ({ id: s.name, group: s.ip }));
                const links = topo.connections.map(c => ({ source: c.source, target: c.target, label: c.protocol }));
                const container = document.getElementById('topology-graph');
                container.innerHTML = '';
                const width = container.clientWidth;
                const height = container.clientHeight;
                const svg = d3.select('#topology-graph').append('svg').attr('width', width).attr('height', height);
                const simulation = d3.forceSimulation(nodes)
                    .force('link', d3.forceLink(links).id(d => d.id).distance(80))
                    .force('charge', d3.forceManyBody().strength(-300))
                    .force('center', d3.forceCenter(width/2, height/2));
                const link = svg.append('g').selectAll('line').data(links).enter().append('line')
                    .attr('stroke', '#6c757d').attr('stroke-width', 2);
                const node = svg.append('g').selectAll('circle').data(nodes).enter().append('circle')
                    .attr('r', 12).attr('fill', '#0d6efd')
                    .call(d3.drag().on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
                    .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
                    .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));
                const label = svg.append('g').selectAll('text').data(nodes).enter().append('text')
                    .text(d => d.id).attr('font-size', '10px').attr('dx', 15).attr('dy', 4).attr('fill', 'white');
                simulation.on('tick', () => {
                    link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
                    node.attr('cx', d => d.x).attr('cy', d => d.y);
                    label.attr('x', d => d.x).attr('y', d => d.y);
                });
            });

        // Simulate attack function
        async function simulateAttack(findingIds) {
            const modal = new bootstrap.Modal(document.getElementById('simulationModal'));
            modal.show();
            const resultDiv = document.getElementById('simulation-result');
            resultDiv.innerHTML = '<div class="text-center"><div class="spinner-border" style="color:var(--accent)"></div><p class="mt-2">Simulating attack chain...</p></div>';
            try {
                const resp = await fetch('/api/simulate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', ...getHeaders() },
                    body: JSON.stringify({ finding_ids: findingIds })
                });
                const data = await resp.json();
                resultDiv.innerHTML = `
                    <h6 style="color:var(--accent)">Simulation Results</h6>
                    <pre class="bg-dark p-3 rounded" style="color:var(--text); max-height:300px; overflow-y:auto;">${escapeHtml(data.script)}</pre>
                    <p class="mt-2"><strong>Description:</strong> ${escapeHtml(data.description)}</p>
                    ${data.sandbox_output ? `<p><strong>Sandbox Output:</strong><br><pre>${escapeHtml(data.sandbox_output)}</pre></p>` : ''}
                `;
            } catch (err) {
                resultDiv.innerHTML = `<div class="alert alert-danger">Simulation failed: ${err.message}</div>`;
            }
        }

        function escapeHtml(text) {
            return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }
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

@dashboard_bp.route('/api/simulate', methods=['POST'])
def api_simulate():
    """Simulate an attack chain based on a list of finding IDs."""
    data = request.get_json(force=True)
    finding_ids = data.get('finding_ids', [])
    if not finding_ids:
        return jsonify({"error": "No finding IDs provided"}), 400

    # Retrieve full findings from the database (or from current session)
    findings = load_findings()
    selected = [f for f in findings if f.get('id') in finding_ids]
    if not selected:
        return jsonify({"error": "No matching findings found"}), 404

    # Generate a combined attack script
    import tempfile, subprocess
    from devsecops_radar.core.attack_simulation import simulate_attack, run_sandboxed_poc
    script_parts = []
    descriptions = []
    for f in selected:
        script_path = simulate_attack(f)
        with open(script_path) as sf:
            script_parts.append(sf.read())
        descriptions.append(f"{f.get('id')}: {f.get('title')}")

    full_script = "\n".join(script_parts)
    description = " → ".join(descriptions)

    # Optionally run in sandbox (safeguarded)
    sandbox_output = None
    try:
        sandbox_output = run_sandboxed_poc(script_path) if script_path else None
    except:
        pass

    return jsonify({
        "script": full_script,
        "description": description,
        "sandbox_output": sandbox_output
    })

# The following routes are expected to exist in other Blueprints (attack_paths, topology, summary, sentry)