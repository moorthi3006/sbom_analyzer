import os
from uuid import uuid4

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from werkzeug.utils import secure_filename

from backend.services.sbom_processor import SBOMProcessor
from backend import db
from backend.utils.helpers import csrf_protect, login_required, allowed_file

upload_bp = Blueprint("upload", __name__, url_prefix="/upload")


@upload_bp.route("/", methods=["GET", "POST"])
@login_required
@csrf_protect
def index():
    if request.method == "POST":
        if "sbom_file" not in request.files:
            flash("No file selected.", "danger")
            return redirect(request.url)

        file = request.files["sbom_file"]
        if file.filename == "":
            flash("No file selected.", "danger")
            return redirect(request.url)

        if not allowed_file(file.filename, current_app.config["ALLOWED_EXTENSIONS"]):
            flash("Invalid file type. Only JSON and CSV are supported.", "danger")
            return redirect(request.url)

        application_name = request.form.get("application_name", "").strip()
        owner = request.form.get("owner", "").strip()
        criticality = request.form.get("criticality", "medium")

        if not application_name or not owner:
            flash("Application name and owner are required.", "danger")
            return redirect(request.url)
        if len(application_name) > 150 or len(owner) > 100 or criticality not in {"low", "medium", "high", "critical"}:
            flash("Please provide valid application details.", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        ext = filename.rsplit(".", 1)[1].lower()
        filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], f"{uuid4().hex}.{ext}")
        file.save(filepath)

        try:
            processor = SBOMProcessor(current_app.config)
            app, scan = processor.process_upload(
                filepath, ext, application_name, owner, criticality, current_app.config
            )
            flash(
                f"SBOM processed successfully. {scan.dependency_count} dependencies, "
                f"{scan.vulnerability_count} vulnerabilities found. Risk score: {app.risk_score}",
                "success",
            )
            return redirect(url_for("applications.detail", app_id=app.id))
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("SBOM processing failed")
            flash("The SBOM could not be processed. Check that it is a valid supported SBOM and try again.", "danger")
            return redirect(request.url)

    return render_template("upload.html")
