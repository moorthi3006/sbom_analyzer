import os

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app
from sqlalchemy import or_

from backend import db
from backend.models import Application, Report, Scan
from backend.services.report_generator import PDFReportGenerator
from backend.utils.helpers import login_required
from backend.models import Vulnerability, Dependency, LicenseRecord
import io, csv

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def index():
    search_query = request.args.get("search", "").strip()
    application_filter = request.args.get("application_id", type=int)
    page = request.args.get("page", 1, type=int)
    per_page = 10

    report_query = Report.query.join(Application)
    if application_filter:
        report_query = report_query.filter(Report.application_id == application_filter)
    if search_query:
        report_query = report_query.filter(
            or_(
                Report.filename.ilike(f"%{search_query}%"),
                Application.name.ilike(f"%{search_query}%")
            )
        )

    report_query = report_query.order_by(Report.generated_at.desc())
    reports = report_query.paginate(page=page, per_page=per_page, error_out=False)
    applications = Application.query.order_by(Application.name).all()
    scan_history = Scan.query.order_by(Scan.created_at.desc()).limit(6).all()

    filtered_reports = reports.items
    total_reports = reports.total
    unique_applications = report_query.with_entities(Report.application_id).distinct().count()
    high_risk_reports = sum(
        1 for report in report_query.all()
        if report.application and report.application.risk_level in ["high", "critical"]
    )
    average_risk_score = 0
    risk_scores = [report.application.risk_score for report in report_query.all() if report.application]
    if risk_scores:
        average_risk_score = sum(risk_scores) / len(risk_scores)

    return render_template(
        "reports.html",
        reports=filtered_reports,
        applications=applications,
        scan_history=scan_history,
        total_reports=total_reports,
        unique_applications=unique_applications,
        high_risk_reports=high_risk_reports,
        average_risk_score=average_risk_score,
        search_query=search_query,
        application_filter=application_filter,
        pagination=reports,
        page=page,
    )


@reports_bp.route("/generate", methods=["POST"])
@login_required
def generate():
    app_id = request.form.get("application_id", type=int)
    if not app_id:
        flash("Please select an application.", "warning")
        return redirect(url_for("reports.index"))

    app = Application.query.get_or_404(app_id)
    latest_scan = Scan.query.filter_by(application_id=app_id).order_by(Scan.created_at.desc()).first()

    try:
        generator = PDFReportGenerator()
        filename, filepath = generator.generate(
            app_id,
            latest_scan.id if latest_scan else None,
            current_app.config["REPORTS_FOLDER"],
        )

        report = Report(
            application_id=app_id,
            scan_id=latest_scan.id if latest_scan else None,
            filename=filename,
            filepath=filepath,
        )
        db.session.add(report)
        db.session.commit()

        flash(f"Report generated: {filename}", "success")
    except Exception as e:
        flash(f"Error generating report: {str(e)}", "danger")

    return redirect(url_for("reports.index"))


@reports_bp.route("/download/<int:report_id>")
@login_required
def download(report_id):
    report = Report.query.get_or_404(report_id)
    if not os.path.exists(report.filepath):
        flash("Report file not found.", "danger")
        return redirect(url_for("reports.index"))

    return send_file(report.filepath, as_attachment=True, download_name=report.filename)


@reports_bp.route('/download_csv/<int:report_id>')
@login_required
def download_csv(report_id):
    report = Report.query.get_or_404(report_id)
    app_id = report.application_id
    # collect vulnerabilities for application
    vulns = (
        db.session.query(Vulnerability)
        .join(Dependency, Dependency.id == Vulnerability.dependency_id)
        .filter(Dependency.application_id == app_id)
        .order_by(Vulnerability.cvss_score.desc())
        .all()
    )
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['cve_id','severity','cvss_score','package','version','patch_available','published_date','description'])
    for v in vulns:
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
    output.headers['Content-Disposition'] = f'attachment; filename=report_{report.id}_vulnerabilities.csv'
    output.headers['Content-type'] = 'text/csv'
    return output


@reports_bp.route('/print/<int:report_id>')
@login_required
def print_report(report_id):
    report = Report.query.get_or_404(report_id)
    app = Application.query.get(report.application_id)
    deps = Dependency.query.filter_by(application_id=app.id).all()
    all_vulns = []
    for d in deps:
        for v in d.vulnerabilities:
            all_vulns.append(v)
    # compute simple stats
    conflicts = LicenseRecord.query.filter_by(compatibility='conflict').count()
    outdated = sum(1 for d in deps if d.is_outdated)
    maintenance_score = 100 - (outdated / len(deps) * 100) if deps else 100

    top_vulns = sorted(all_vulns, key=lambda v: v.cvss_score, reverse=True)[:15]

    return render_template('report_print.html', report=report, app=app, deps=deps, top_vulns=top_vulns, conflicts=conflicts, maintenance_score=maintenance_score)
