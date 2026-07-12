from flask import Blueprint, render_template, session, jsonify

from backend.services.dashboard_analytics import DashboardAnalytics
from backend.utils.helpers import login_required

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@dashboard_bp.route("/")
@login_required
def index():
    analytics = DashboardAnalytics()
    return render_template(
        "dashboard.html",
        username=session.get("username"),
        cards=analytics.get_summary_cards(),
        risk_distribution=analytics.get_risk_distribution(),
        severity_distribution=analytics.get_severity_distribution(),
        recent_scans=analytics.get_recent_scans(),
        recent_vulnerabilities=analytics.get_recent_vulnerabilities(),
        recent_reports=analytics.get_recent_reports(),
        top_risk_apps=analytics.get_top_risk_applications(),
        top_vulnerable_apps=analytics.get_top_vulnerable_applications(),
        license_conflicts=analytics.get_license_conflict_count(),
        outdated_count=analytics.get_outdated_count(),
        scan_trend=analytics.get_scan_trend(),
    )


@dashboard_bp.route('/api')
@login_required
def api_dashboard():
    analytics = DashboardAnalytics()
    data = {
        'cards': analytics.get_summary_cards(),
        'risk_distribution': analytics.get_risk_distribution(),
        'severity_distribution': analytics.get_severity_distribution(),
        'scan_trend': analytics.get_scan_trend(),
        'top_vulnerable_apps': analytics.get_top_vulnerable_applications(),
    }
    return jsonify(data)
