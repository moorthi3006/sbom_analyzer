function initDependencyGraph(graphData) {
    const canvas = document.getElementById('depGraphCanvas');
    if (!canvas || !graphData || !graphData.nodes.length) return;

    const ctx = canvas.getContext('2d');
    const container = document.getElementById('graphCanvas');
    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight;

    const nodeSize = 120;
    const levelSpacing = 120;

    const nodes = graphData.nodes.map(function (n) {
        return {
            ...n,
            width: nodeSize,
            height: 42,
            x: 0,
            y: 0,
        };
    });
    // expose node layout for other UI handlers (click -> modal)
    window._depGraphNodes = nodes;

    const roots = nodes.filter(function (n) {
        return !graphData.edges.some(function (e) { return e.target === n.id; });
    });

    function getChildren(nodeId) {
        return graphData.edges
            .filter(function (e) { return e.source === nodeId; })
            .map(function (e) { return nodes.find(function (n) { return n.id === e.target; }); })
            .filter(Boolean);
    }

    function layoutTree(node, depth, offsetX) {
        const children = getChildren(node.id);
        const x = offsetX;
        const y = depth * levelSpacing + 40;
        node.x = x;
        node.y = y;

        let childX = x - ((children.length - 1) * (nodeSize + 40)) / 2;
        children.forEach(function (child) {
            layoutTree(child, depth + 1, childX);
            childX += nodeSize + 40;
        });
    }

    let currentX = canvas.width / 2 - ((roots.length - 1) * (nodeSize + 40)) / 2;
    roots.forEach(function (root) {
        layoutTree(root, 0, currentX);
        currentX += nodeSize + 40;
    });

    const tooltip = document.getElementById('graphTooltip');

    function draw() {
        ctx.clearRect(0, 0, 0, canvas.width, canvas.height);

        graphData.edges.forEach(function (edge) {
            const source = nodes.find(function (n) { return n.id === edge.source; });
            const target = nodes.find(function (n) { return n.id === edge.target; });
            if (!source || !target) return;

            const startX = source.x + source.width / 2;
            const startY = source.y + source.height;
            const endX = target.x + target.width / 2;
            const endY = target.y;

            ctx.beginPath();
            ctx.moveTo(startX, startY);
            ctx.lineTo(startX, startY + 16);
            ctx.lineTo(endX, startY + 16);
            ctx.lineTo(endX, endY);
            ctx.strokeStyle = 'rgba(74, 158, 255, 0.6)';
            ctx.lineWidth = 2;
            ctx.stroke();

            ctx.beginPath();
            ctx.moveTo(endX - 6, endY - 8);
            ctx.lineTo(endX + 6, endY - 8);
            ctx.lineTo(endX, endY);
            ctx.fillStyle = 'rgba(74, 158, 255, 0.8)';
            ctx.fill();
        });

        nodes.forEach(function (node) {
            const depth = node.depth || 0;
            const colors = ['#00d4aa', '#4a9eff', '#ffc107', '#dc3545', '#6f42c1'];
            const fill = colors[Math.min(depth, colors.length - 1)];

            const isVuln = node.is_vulnerable || node.vuln_count > 0;
            ctx.fillStyle = isVuln ? '#8b0000' : fill;
            ctx.strokeStyle = isVuln ? '#5a0000' : '#1f3252';
            ctx.lineWidth = 2;
            ctx.fillRect(node.x, node.y, node.width, node.height);
            ctx.strokeRect(node.x, node.y, node.width, node.height);

            ctx.fillStyle = '#ffffff';
            ctx.font = '600 12px Segoe UI';
            ctx.textAlign = 'left';
            ctx.fillText(node.label || '', node.x + 10, node.y + 16);

            ctx.font = '10px Segoe UI';
            ctx.fillStyle = 'rgba(255,255,255,0.85)';
            ctx.fillText('@' + (node.version || ''), node.x + 10, node.y + 32);
        });
    }

    function updateTooltip(event) {
        if (!tooltip) return;
        const rect = canvas.getBoundingClientRect();
        const mouseX = event.clientX - rect.left;
        const mouseY = event.clientY - rect.top;
        const hovered = nodes.find(function (node) {
            return mouseX >= node.x && mouseX <= node.x + node.width && mouseY >= node.y && mouseY <= node.y + node.height;
        });

        if (hovered) {
            tooltip.classList.remove('d-none');
            tooltip.style.left = `${Math.min(rect.width - 220, mouseX + 18)}px`;
            tooltip.style.top = `${Math.max(8, mouseY - 10)}px`;
            tooltip.innerHTML = `<strong>${hovered.label}</strong><br><span class="text-muted">@${hovered.version}</span><br><small>Depth ${hovered.depth}</small>`;
            canvas.style.cursor = 'pointer';
        } else {
            tooltip.classList.add('d-none');
            canvas.style.cursor = 'default';
        }
    }

    canvas.addEventListener('mousemove', updateTooltip);
    canvas.addEventListener('mouseout', function () {
        if (tooltip) tooltip.classList.add('d-none');
        canvas.style.cursor = 'default';
    });

    draw();
}

// Tree UI: expand/collapse, search, click-to-open details
document.addEventListener('DOMContentLoaded', function () {
    // expand/collapse
    document.querySelectorAll('.tree-box .btn-toggle').forEach(function (btn) {
        btn.addEventListener('click', function (e) {
            e.preventDefault();
            const li = btn.closest('li');
            const children = li.querySelector('.tree-children');
            if (!children) return;
            const expanded = btn.getAttribute('aria-expanded') === 'true';
            if (expanded) {
                children.style.display = 'none';
                btn.setAttribute('aria-expanded', 'false');
                btn.innerHTML = '<i class="bi bi-plus-lg"></i>';
            } else {
                children.style.display = '';
                btn.setAttribute('aria-expanded', 'true');
                btn.innerHTML = '<i class="bi bi-dash-lg"></i>';
            }
        });
    });

    // search filter
    const search = document.getElementById('packageSearch');
    if (search) {
        search.addEventListener('input', function () {
            const q = search.value.trim().toLowerCase();
            document.querySelectorAll('#treeContainer .tree-box').forEach(function (box) {
                const name = box.querySelector('strong') ? box.querySelector('strong').textContent.toLowerCase() : '';
                if (!q || name.indexOf(q) !== -1) {
                    box.parentElement.style.display = '';
                    box.classList.add('highlight');
                } else {
                    box.parentElement.style.display = 'none';
                    box.classList.remove('highlight');
                }
            });
        });
    }

    // click to open package details modal
    function openPackageModal(data) {
        let modal = document.getElementById('pkgDetailsModal');
        if (!modal) return;
        const titleEl = modal.querySelector('.modal-pkg-name');
        if (titleEl) titleEl.textContent = data.name || '';
        const ver = modal.querySelector('.pkg-version'); if (ver) ver.textContent = data.version || '';
        const depthEl = modal.querySelector('.pkg-depth'); if (depthEl) depthEl.textContent = data.depth || '';
        const vulnEl = modal.querySelector('.pkg-vuln-count'); if (vulnEl) vulnEl.textContent = data.vuln_count || 0;
        const riskEl = modal.querySelector('.pkg-risk'); if (riskEl) riskEl.textContent = data.risk_contribution || 0;
        const viewVulns = modal.querySelector('.view-vulns');
        if (viewVulns) {
            viewVulns.setAttribute('href', '/vulnerabilities/?dep_id=' + (data.id || ''));
        }
        const bs = new bootstrap.Modal(modal);
        bs.show();
    }

    document.querySelectorAll('#treeContainer .tree-box').forEach(function (box) {
        box.addEventListener('click', function (e) {
            // avoid toggle button
            if (e.target.closest('.btn-toggle')) return;
            const id = box.getAttribute('data-dep-id');
            const name = box.querySelector('strong') ? box.querySelector('strong').textContent : '';
            const version = box.querySelector('.tree-box-meta .text-muted') ? box.querySelector('.tree-box-meta .text-muted').textContent.replace('@','') : '';
            const depth = box.getAttribute('data-depth');
            const vuln_count = box.getAttribute('data-vuln-count');
            const risk = box.querySelector('.badge.bg-danger') ? box.querySelector('.badge.bg-danger').textContent : '';
            openPackageModal({ id: id, name: name, version: version, depth: depth, vuln_count: vuln_count, risk_contribution: risk });
        });
    });

    // graph canvas click -> open modal for hovered node
    const canvas = document.getElementById('depGraphCanvas');
    if (canvas) {
        canvas.addEventListener('click', function (e) {
            const rect = canvas.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;
            if (window._depGraphNodes) {
                const node = window._depGraphNodes.find(function (n) {
                    return mouseX >= n.x && mouseX <= n.x + n.width && mouseY >= n.y && mouseY <= n.y + n.height;
                });
                if (node) {
                    openPackageModal({ id: node.id, name: node.label, version: node.version, depth: node.depth, vuln_count: node.vuln_count || 0, risk_contribution: node.risk_contribution || 0 });
                }
            }
        });
    }
});
