from flask import Blueprint, render_template, request, jsonify

from backend.models import Application
from backend.services.dependency_graph import DependencyGraphBuilder
from backend.utils.helpers import login_required

dependencies_bp = Blueprint("dependencies", __name__, url_prefix="/dependencies")


@dependencies_bp.route("/")
@login_required
def index():
    applications = Application.query.order_by(Application.name).all()
    selected_id = request.args.get("app_id", type=int)
    if not selected_id and applications:
        selected_id = applications[0].id

    tree_data = []
    graph_data = {"nodes": [], "edges": []}
    graph_image = None

    if selected_id:
        builder = DependencyGraphBuilder()
        tree_data = builder.get_tree_data(selected_id)
        graph_data = builder.get_graph_data(selected_id)
        from flask import current_app
        import os
        img_path = os.path.join(current_app.config["GRAPHS_FOLDER"], f"dep_graph_{selected_id}.png")
        if os.path.exists(img_path):
            graph_image = f"/graphs/dep_graph_{selected_id}.png"

    return render_template(
        "dependencies.html",
        applications=applications,
        selected_id=selected_id,
        tree_data=tree_data,
        graph_data=graph_data,
        graph_image=graph_image,
    )


@dependencies_bp.route("/api/tree/<int:app_id>")
@login_required
def api_tree(app_id):
    builder = DependencyGraphBuilder()
    return jsonify(builder.get_tree_data(app_id))


@dependencies_bp.route("/api/graph/<int:app_id>")
@login_required
def api_graph(app_id):
    builder = DependencyGraphBuilder()
    return jsonify(builder.get_graph_data(app_id))
