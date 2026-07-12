from flask import Blueprint, render_template, request

from backend.models import Dependency, Application
from backend.utils.helpers import login_required, risk_badge_class

maintenance_bp = Blueprint("maintenance", __name__, url_prefix="/maintenance")


@maintenance_bp.route("/")
@login_required
def index():
    app_filter = request.args.get("app_id", type=int)
    risk_filter = request.args.get("risk", "")

    query = Dependency.query.filter_by(is_outdated=True)

    if app_filter:
        query = query.filter_by(application_id=app_filter)
    if risk_filter:
        query = query.filter_by(maintenance_risk=risk_filter)

    outdated_deps = query.order_by(Dependency.last_updated.asc()).limit(100).all()

    stats = {
        "total_outdated": Dependency.query.filter_by(is_outdated=True).count(),
        "critical": Dependency.query.filter_by(maintenance_risk="critical", is_outdated=True).count(),
        "high": Dependency.query.filter_by(maintenance_risk="high", is_outdated=True).count(),
        "medium": Dependency.query.filter_by(maintenance_risk="medium", is_outdated=True).count(),
    }

    applications = Application.query.order_by(Application.name).all()

    return render_template(
        "maintenance.html",
        outdated_deps=outdated_deps,
        stats=stats,
        applications=applications,
        app_filter=app_filter,
        risk_filter=risk_filter,
        risk_badge_class=risk_badge_class,
    )
