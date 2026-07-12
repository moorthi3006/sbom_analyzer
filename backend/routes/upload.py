import os

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify
from werkzeug.utils import secure_filename

from backend.services.sbom_processor import SBOMProcessor
from backend.utils.helpers import login_required, allowed_file

upload_bp = Blueprint("upload", __name__, url_prefix="/upload")


@upload_bp.route("/", methods=["GET", "POST"])
@login_required
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

        filename = secure_filename(file.filename)
        ext = filename.rsplit(".", 1)[1].lower()
        filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
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
            flash(f"Error processing SBOM: {str(e)}", "danger")
            return redirect(request.url)

    return render_template("upload.html")


@upload_bp.route('/api', methods=['POST'])
@login_required
def api_upload():
    if 'sbom_file' not in request.files:
        return jsonify(success=False, message='No file selected.'), 400

    file = request.files['sbom_file']
    if file.filename == '':
        return jsonify(success=False, message='No file selected.'), 400

    if not allowed_file(file.filename, current_app.config['ALLOWED_EXTENSIONS']):
        return jsonify(success=False, message='Invalid file type. Only JSON and CSV are supported.'), 400

    application_name = request.form.get('application_name', '').strip()
    owner = request.form.get('owner', '').strip()
    criticality = request.form.get('criticality', 'medium')

    if not application_name or not owner:
        return jsonify(success=False, message='Application name and owner are required.'), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[1].lower()
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        processor = SBOMProcessor(current_app.config)
        app, scan = processor.process_upload(
            filepath, ext, application_name, owner, criticality, current_app.config
        )
        msg = f"SBOM processed successfully. {scan.dependency_count} dependencies, {scan.vulnerability_count} vulnerabilities found. Risk score: {app.risk_score}"
        return jsonify(success=True, message=msg, redirect=url_for('applications.detail', app_id=app.id))
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500
