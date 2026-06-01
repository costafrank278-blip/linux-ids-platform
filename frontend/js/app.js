const API_BASE = '/api';
const REFRESH_INTERVAL_MS = window.DASHBOARD_REFRESH_INTERVAL_MS || 5000;

let typeChart;
let severityChart;

async function fetchJSON(url) {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    return response.json();
}

function badgeClassBySeverity(severity = '') {
    const normalized = (severity || '').toLowerCase();
    if (['critical', 'high', 'medium', 'low'].includes(normalized)) {
        return `badge badge-${normalized}`;
    }
    return 'badge bg-secondary';
}

function badgeClassByStatus(status = '') {
    const normalized = (status || '').toLowerCase();
    if (normalized === 'new') return 'badge badge-new';
    if (normalized === 'reviewed') return 'badge badge-reviewed';
    return 'badge bg-secondary';
}

function formatTimestamp(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts;
    return d.toLocaleString('pt-BR');
}

function renderAlertsTable(alerts) {
    const tbody = document.querySelector('#alerts-table tbody');
    tbody.innerHTML = '';

    if (!alerts.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Sem alertas no momento</td></tr>';
        return;
    }

    alerts.forEach((alert) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${formatTimestamp(alert.timestamp)}</td>
            <td>${alert.threat_type || '-'}</td>
            <td><span class="${badgeClassBySeverity(alert.severity)}">${alert.severity || '-'}</span></td>
            <td>${alert.source_ip || '-'}</td>
            <td>${alert.description || '-'}</td>
            <td><span class="${badgeClassByStatus(alert.status)}">${alert.status || '-'}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderTopIps(items) {
    const container = document.getElementById('top-ips-container');
    container.innerHTML = '';

    if (!items.length) {
        container.innerHTML = '<div class="text-muted">Nenhum IP ameaçador identificado</div>';
        return;
    }

    items.forEach(({ ip, alert_count }) => {
        const div = document.createElement('div');
        div.className = 'ip-threat d-flex justify-content-between align-items-center';
        div.innerHTML = `
            <strong>${ip}</strong>
            <span class="count">${alert_count} alertas</span>
        `;
        container.appendChild(div);
    });
}

function renderTypeChart(items) {
    const labels = items.map((item) => item.type);
    const values = items.map((item) => item.count);

    if (!typeChart) {
        typeChart = new Chart(document.getElementById('alertsByTypeChart').getContext('2d'), {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    label: 'Alertas',
                    data: values,
                    backgroundColor: '#0d6efd'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } }
            }
        });
    } else {
        typeChart.data.labels = labels;
        typeChart.data.datasets[0].data = values;
        typeChart.update();
    }
}

function renderSeverityChart(data) {
    const labels = Object.keys(data);
    const values = Object.values(data);
    const colorMap = {
        critical: '#dc3545',
        high: '#fd7e14',
        medium: '#ffc107',
        low: '#0dcaf0'
    };
    const colors = labels.map((label) => colorMap[label] || '#6c757d');

    if (!severityChart) {
        severityChart = new Chart(document.getElementById('alertsBySeverityChart').getContext('2d'), {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{ data: values, backgroundColor: colors }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    } else {
        severityChart.data.labels = labels;
        severityChart.data.datasets[0].data = values;
        severityChart.data.datasets[0].backgroundColor = colors;
        severityChart.update();
    }
}

async function refreshDashboard() {
    try {
        const [overview, alertsData, byType, bySeverity, topIps] = await Promise.all([
            fetchJSON(`${API_BASE}/stats/overview`),
            fetchJSON(`${API_BASE}/alerts/?limit=20`),
            fetchJSON(`${API_BASE}/stats/by-type`),
            fetchJSON(`${API_BASE}/stats/by-severity`),
            fetchJSON(`${API_BASE}/stats/top-ips`)
        ]);

        document.getElementById('total-alerts').textContent = overview.total_alerts ?? 0;
        document.getElementById('critical-alerts').textContent = overview.critical_alerts ?? 0;
        document.getElementById('alerts-24h').textContent = overview.alerts_24h ?? 0;
        document.getElementById('unique-ips').textContent = overview.unique_source_ips ?? 0;

        renderAlertsTable(alertsData.alerts || []);
        renderTypeChart(byType || []);
        renderSeverityChart(bySeverity || {});
        renderTopIps(topIps || []);

        document.getElementById('status').className = 'badge bg-success';
        document.getElementById('status').textContent = 'Online';
    } catch (error) {
        console.error('Erro ao atualizar dashboard:', error);
        document.getElementById('status').className = 'badge bg-danger';
        document.getElementById('status').textContent = 'Offline';
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    await refreshDashboard();
    setInterval(refreshDashboard, REFRESH_INTERVAL_MS);
});
