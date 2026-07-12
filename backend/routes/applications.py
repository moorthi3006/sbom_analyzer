from flask import Blueprint, render_template, request, redirect, url_for, flash
from sqlalchemy import or_

from backend import db
from backend.models import Application, Scan
from backend.utils.helpers import login_required, risk_badge_class

applications_bp = Blueprint("applications", __name__, url_prefix="/applications")


@applications_bp.route("/")
@login_required
def index():
    sort = request.args.get("sort", "risk_score")
    order = request.args.get("order", "desc")
    search_query = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "")
    criticality_filter = request.args.get("criticality", "")
    page = request.args.get("page", 1, type=int)
    per_page = 10

    query = Application.query
    if search_query:
        query = query.filter(
            or_(
                Application.name.ilike(f"%{search_query}%"),
                Application.owner.ilike(f"%{search_query}%")
            )
        )
    if status_filter:
        # filter by latest scan status
        sub = db.session.query(Scan.application_id).filter(Scan.status == status_filter).subquery()
        query = query.filter(Application.id.in_(sub))
    if criticality_filter:
        query = query.filter(Application.business_criticality == criticality_filter)

    if sort == "name":
        query = query.order_by(Application.name.asc() if order == "asc" else Application.name.desc())
    elif sort == "criticality":
        query = query.order_by(Application.business_criticality.asc() if order == "asc" else Application.business_criticality.desc())
    elif sort == "status":
        query = query.order_by(Application.updated_at.asc() if order == "asc" else Application.updated_at.desc())
    else:
        query = query.order_by(Application.risk_score.asc() if order == "asc" else Application.risk_score.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    applications = pagination.items

    # prepare last scan lookup for displayed applications
    last_scan_map = {}
    for a in applications:
        last = a.scans.order_by(Scan.created_at.desc()).first()
        last_scan_map[a.id] = last

    return render_template(
        "applications.html",
        applications=applications,
        risk_badge_class=risk_badge_class,
        sort=sort,
        order=order,
        search_query=search_query,
        pagination=pagination,
        page=page,
        status_filter=status_filter,
        criticality_filter=criticality_filter,
        last_scan_map=last_scan_map,
    )


@applications_bp.route("/delete/<int:app_id>", methods=["POST"])
@login_required
def delete(app_id):
    app = Application.query.get_or_404(app_id)
    db.session.delete(app)
    db.session.commit()
    flash(f"Application '{app.name}' deleted successfully.", "success")
    return redirect(url_for("applications.index"))

@applications_bp.route('/scan/<int:app_id>', methods=['POST'])
@login_required
def scan(app_id):
    app = Application.query.get_or_404(app_id)
    # create a queued scan entry
    s = Scan(application_id=app.id, filename=f"scan_{app.id}", status='queued', risk_score=0.0)
    db.session.add(s)
    db.session.commit()
    flash(f"Scan scheduled for '{app.name}'.", "info")
    return redirect(url_for('applications.index'))

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
