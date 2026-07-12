function initDashboardCharts(riskDist, severityDist, scanTrend, topApps) {
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
        const totalRisk = riskDist.low + riskDist.medium + riskDist.high + riskDist.critical;

        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['Low', 'Medium', 'High', 'Critical'],
                datasets: [{
                    data: [riskDist.low, riskDist.medium, riskDist.high, riskDist.critical],
                    backgroundColor: ['#00d4aa', '#ffc107', '#dc3545', '#212529'],
                    borderColor: '#0a1628',
                    borderWidth: 2,
                    hoverOffset: 8
                }]
            },
            options: {
                ...chartDefaults,
                cutout: '72%',
                plugins: {
                    ...chartDefaults.plugins,
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#8892b0',
                            boxWidth: 12,
                            padding: 16
                        }
                    },
                    tooltip: {
                        backgroundColor: '#111f3f',
                        titleColor: '#ffffff',
                        bodyColor: '#d1e0ff',
                        borderColor: '#233554',
                        borderWidth: 1,
                        callbacks: {
                            label: context => `${context.label}: ${context.parsed} items`
                        }
                    }
                },
                layout: { padding: 12 }
            },
            plugins: [{
                id: 'riskTotalCenter',
                afterDraw: chart => {
                    const { ctx, chartArea: { width, height, left, top } } = chart;
                    ctx.save();
                    ctx.fillStyle = '#d1e0ff';
                    ctx.textAlign = 'center';
                    ctx.font = '600 1rem "Segoe UI", sans-serif';
                    ctx.fillText('Total', left + width / 2, top + height / 2 - 10);
                    ctx.font = '700 1.6rem "Segoe UI", sans-serif';
                    ctx.fillText(totalRisk, left + width / 2, top + height / 2 + 24);
                    ctx.restore();
                }
            }]
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

    // Top 10 vulnerable applications - horizontal bar
    const topCtx = document.getElementById('topAppsChart');
    if (topCtx && Array.isArray(topApps) && topApps.length) {
        const labels = topApps.map(a => a.name);
        const counts = topApps.map(a => a.vuln_count);
        new Chart(topCtx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'CVEs',
                    data: counts,
                    backgroundColor: '#dc3545',
                    borderRadius: 6
                }]
            },
            options: {
                ...chartDefaults,
                indexAxis: 'y',
                scales: {
                    x: { ticks: { color: '#8892b0' }, grid: { color: '#233554' } },
                    y: { ticks: { color: '#8892b0' }, grid: { color: 'transparent' } }
                },
                plugins: {
                    ...chartDefaults.plugins,
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: context => `${context.parsed.x} CVEs`
                        }
                    }
                }
            }
        });
    }
}
