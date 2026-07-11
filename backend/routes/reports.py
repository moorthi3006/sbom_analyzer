import os

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app

from backend import db
from backend.models import Application, Report, Scan
from backend.services.report_generator import PDFReportGenerator
from backend.utils.helpers import login_required

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def index():
    reports = Report.query.order_by(Report.generated_at.desc()).all()
    applications = Application.query.order_by(Application.name).all()
    return render_template("reports.html", reports=reports, applications=applications)


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
