from flask import Blueprint, render_template, request, make_response

from backend.models import Vulnerability, Dependency, Application
from backend.utils.helpers import login_required, severity_badge_class

vulnerabilities_bp = Blueprint("vulnerabilities", __name__, url_prefix="/vulnerabilities")


@vulnerabilities_bp.route("/")
@login_required
def index():
    severity_filter = request.args.get("severity", "")
    search = request.args.get("search", "").strip()
    patch_filter = request.args.get("patch", "")

    query = Vulnerability.query.join(Dependency)

    if severity_filter:
        query = query.filter(Vulnerability.severity == severity_filter)
    if search:
        query = query.filter(
            db_or(Vulnerability.cve_id.ilike(f"%{search}%"),
                  Vulnerability.description.ilike(f"%{search}%"),
                  Dependency.name.ilike(f"%{search}%"))
        )
    if patch_filter == "yes":
        query = query.filter(Vulnerability.patch_available.is_(True))
    elif patch_filter == "no":
        query = query.filter(Vulnerability.patch_available.is_(False))

    # If export requested, return CSV of matching results
    export = request.args.get("export", "")
    vulnerabilities_q = query.order_by(Vulnerability.cvss_score.desc())
    if export == 'csv':
        results = vulnerabilities_q.all()
        # build CSV
        import io, csv
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['cve_id', 'severity', 'cvss_score', 'package', 'version', 'patch_available', 'published_date', 'description'])
        for v in results:
            cw.writerow([
                v.cve_id,
                v.severity,
                v.cvss_score,
                v.dependency.name if v.dependency else '',
                v.dependency.version if v.dependency else '',
                'yes' if v.patch_available else 'no',
                v.published_date.strftime('%Y-%m-%d') if v.published_date else '',
                (v.description or '').replace('\n',' '),
            ])
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=vulnerabilities.csv"
        output.headers["Content-type"] = "text/csv"
        return output

    vulnerabilities = vulnerabilities_q.limit(200).all()

    stats = {
        "total": Vulnerability.query.count(),
        "critical": Vulnerability.query.filter_by(severity="critical").count(),
        "high": Vulnerability.query.filter_by(severity="high").count(),
        "patched": Vulnerability.query.filter_by(patch_available=True).count(),
    }

    return render_template(
        "vulnerabilities.html",
        vulnerabilities=vulnerabilities,
        stats=stats,
        severity_filter=severity_filter,
        search=search,
        patch_filter=patch_filter,
        severity_badge_class=severity_badge_class,
    )


def db_or(*criteria):
    from sqlalchemy import or_
    return or_(*criteria)
