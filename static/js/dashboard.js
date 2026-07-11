function initDashboardCharts(riskDist, severityDist, scanTrend) {
    const chartDefaults = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: { color: '#8892b0', font: { size: 11 } }
            }
        }
    };

    const riskCtx = document.getElementById('riskDistChart');
    if (riskCtx) {
        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['Low', 'Medium', 'High', 'Critical'],
                datasets: [{
                    data: [riskDist.low, riskDist.medium, riskDist.high, riskDist.critical],
                    backgroundColor: ['#00d4aa', '#ffc107', '#dc3545', '#212529'],
                    borderWidth: 0
                }]
            },
            options: chartDefaults
        });
    }

    const sevCtx = document.getElementById('severityChart');
    if (sevCtx) {
        new Chart(sevCtx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'CVEs',
                    data: [severityDist.critical, severityDist.high, severityDist.medium, severityDist.low],
                    backgroundColor: ['#212529', '#dc3545', '#ffc107', '#17a2b8'],
                    borderRadius: 4
                }]
            },
            options: {
                ...chartDefaults,
                scales: {
                    x: { ticks: { color: '#8892b0' }, grid: { color: '#233554' } },
                    y: { ticks: { color: '#8892b0' }, grid: { color: '#233554' } }
                },
                plugins: { ...chartDefaults.plugins, legend: { display: false } }
            }
        });
    }

    const trendCtx = document.getElementById('trendChart');
    if (trendCtx && scanTrend.labels.length) {
        new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: scanTrend.labels,
                datasets: [{
                    label: 'Risk Score',
                    data: scanTrend.scores,
                    borderColor: '#4a9eff',
                    backgroundColor: 'rgba(74, 158, 255, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4
                }]
            },
            options: {
                ...chartDefaults,
                scales: {
                    x: { ticks: { color: '#8892b0' }, grid: { color: '#233554' } },
                    y: { ticks: { color: '#8892b0' }, grid: { color: '#233554' } }
                },
                plugins: { ...chartDefaults.plugins, legend: { display: false } }
            }
        });
    }
}
