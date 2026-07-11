function initDependencyGraph(graphData) {
    const canvas = document.getElementById('depGraphCanvas');
    if (!canvas || !graphData || !graphData.nodes.length) return;

    const ctx = canvas.getContext('2d');
    const container = document.getElementById('graphCanvas');
    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight;

    const nodes = graphData.nodes.map(function (n, i) {
        const angle = (2 * Math.PI * i) / graphData.nodes.length;
        const radius = Math.min(canvas.width, canvas.height) * 0.35;
        return {
            ...n,
            x: canvas.width / 2 + radius * Math.cos(angle),
            y: canvas.height / 2 + radius * Math.sin(angle)
        };
    });

    const nodeMap = {};
    nodes.forEach(function (n) { nodeMap[n.id] = n; });

    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        graphData.edges.forEach(function (edge) {
            const source = nodeMap[edge.source];
            const target = nodeMap[edge.target];
            if (!source || !target) return;

            ctx.beginPath();
            ctx.moveTo(source.x, source.y);
            ctx.lineTo(target.x, target.y);
            ctx.strokeStyle = 'rgba(74, 158, 255, 0.4)';
            ctx.lineWidth = 1;
            ctx.stroke();
        });

        nodes.forEach(function (node) {
            const depth = node.depth || 0;
            const colors = ['#00d4aa', '#4a9eff', '#ffc107', '#dc3545', '#6f42c1'];
            const color = colors[Math.min(depth, colors.length - 1)];

            ctx.beginPath();
            ctx.arc(node.x, node.y, 8, 0, 2 * Math.PI);
            ctx.fillStyle = color;
            ctx.fill();

            ctx.fillStyle = '#e6f1ff';
            ctx.font = '10px Segoe UI';
            ctx.textAlign = 'center';
            const label = (node.label || '').substring(0, 15);
            ctx.fillText(label, node.x, node.y + 20);
        });
    }

    draw();
}
