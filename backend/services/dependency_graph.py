import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from backend import db
from backend.models import Dependency
from backend.models import Vulnerability


class DependencyGraphBuilder:
    """Builds dependency trees and graph visualizations using NetworkX."""

    def build_graph(self, application_id):
        deps = Dependency.query.filter_by(application_id=application_id).all()
        graph = nx.DiGraph()

        for dep in deps:
            graph.add_node(dep.id, label=dep.name, version=dep.version, depth=dep.depth)

        for dep in deps:
            if dep.parent_id and dep.parent_id in graph:
                graph.add_edge(dep.parent_id, dep.id)

        return graph

    def get_tree_data(self, application_id):
        deps = Dependency.query.filter_by(application_id=application_id).all()
        dep_map = {d.id: d for d in deps}
        roots = [d for d in deps if d.parent_id is None or d.parent_id not in dep_map]

        def build_node(dep):
            children = [d for d in deps if d.parent_id == dep.id]
            # compute vulnerability count for this dependency
            try:
                vuln_count = Vulnerability.query.filter_by(dependency_id=dep.id).count()
            except Exception:
                vuln_count = 0
            return {
                "id": dep.id,
                "name": dep.name,
                "version": dep.version,
                "depth": dep.depth,
                "risk_contribution": dep.risk_contribution,
                "vuln_count": vuln_count,
                "is_vulnerable": vuln_count > 0,
                "children": [build_node(c) for c in children],
            }

        return [build_node(r) for r in roots]

    def get_graph_data(self, application_id):
        graph = self.build_graph(application_id)
        nodes = []
        for node_id in graph.nodes:
            data = graph.nodes[node_id]
            # try to compute vulnerability count for the node
            try:
                vuln_count = Vulnerability.query.join(Dependency).filter(Dependency.id == node_id).count()
            except Exception:
                vuln_count = 0
            nodes.append({
                "id": node_id,
                "label": data.get("label", ""),
                "version": data.get("version", ""),
                "depth": data.get("depth", 0),
                "vuln_count": vuln_count,
                "is_vulnerable": vuln_count > 0,
            })

        edges = [{"source": u, "target": v} for u, v in graph.edges]
        return {"nodes": nodes, "edges": edges}

    def generate_graph_image(self, application_id, output_dir):
        graph = self.build_graph(application_id)
        if len(graph.nodes) == 0:
            return None

        plt.figure(figsize=(14, 10))
        plt.style.use("dark_background")

        pos = nx.spring_layout(graph, k=2, iterations=50, seed=42)
        depths = [graph.nodes[n].get("depth", 0) for n in graph.nodes]
        node_colors = plt.cm.RdYlGn_r([min(d / 5, 1.0) for d in depths])

        nx.draw_networkx_nodes(graph, pos, node_color=node_colors, node_size=400, alpha=0.9)
        nx.draw_networkx_edges(graph, pos, edge_color="#4a9eff", alpha=0.5, arrows=True, arrowsize=15)
        labels = {n: graph.nodes[n].get("label", "")[:12] for n in graph.nodes}
        nx.draw_networkx_labels(graph, pos, labels, font_size=7, font_color="white")

        plt.title("Dependency Graph", color="white", fontsize=16)
        plt.axis("off")
        plt.tight_layout()

        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, f"dep_graph_{application_id}.png")
        plt.savefig(filepath, dpi=100, facecolor="#0a1628")
        plt.close()
        return filepath
