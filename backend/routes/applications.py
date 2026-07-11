from flask import Blueprint, render_template, request

from backend.models import Application
from backend.utils.helpers import login_required, risk_badge_class

applications_bp = Blueprint("applications", __name__, url_prefix="/applications")


@applications_bp.route("/")
@login_required
def index():
    sort = request.args.get("sort", "risk_score")
    order = request.args.get("order", "desc")

    query = Application.query
    if sort == "name":
        query = query.order_by(Application.name.asc() if order == "asc" else Application.name.desc())
    elif sort == "criticality":
        query = query.order_by(Application.business_criticality.asc() if order == "asc" else Application.business_criticality.desc())
    else:
        query = query.order_by(Application.risk_score.asc() if order == "asc" else Application.risk_score.desc())

    applications = query.all()
    return render_template(
        "applications.html",
        applications=applications,
        risk_badge_class=risk_badge_class,
        sort=sort,
        order=order,
    )


@applications_bp.route("/<int:app_id>")
@login_required
def detail(app_id):
    app = Application.query.get_or_404(app_id)
    from backend.models import Dependency
    deps = app.dependencies.order_by(Dependency.risk_contribution.desc()).limit(20).all()
    return render_template(
        "applications.html",
        applications=[app],
        selected_app=app,
        top_deps=deps,
        risk_badge_class=risk_badge_class,
        detail_mode=True,
    )
