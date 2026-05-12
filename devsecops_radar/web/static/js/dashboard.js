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
            <td>${f.description.length > 80 ? f.description.substring(0,80)+'...' : f.description}</td>
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
        (f.id.toLowerCase().includes(search) || f.description.toLowerCase().includes(search)) &&
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

        const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, UNKNOWN:0};
        data.forEach(f => {
            const sev = f.severity.toUpperCase();
            if (counts.hasOwnProperty(sev)) counts[sev]++;
            else counts.UNKNOWN++;
        });
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                datasets: [{
                    data: [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW],
                    backgroundColor: ['#dc3545','#fd7e14','#0dcaf0','#0d6efd']
                }]
            },
            options: {
                plugins: {
                    legend: { labels: { color: 'white' } }
                }
            }
        });

        document.getElementById('searchInput').addEventListener('input', applyFilters);
        document.getElementById('toolFilter').addEventListener('change', applyFilters);
        document.getElementById('severityFilter').addEventListener('change', applyFilters);
    });