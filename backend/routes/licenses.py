from flask import Blueprint, render_template

from backend.models import LicenseRecord, Dependency, Application
from backend.services.license_checker import LICENSE_MATRIX
from backend.utils.helpers import login_required

licenses_bp = Blueprint("licenses", __name__, url_prefix="/licenses")


@licenses_bp.route("/")
@login_required
def index():
    all_licenses = LicenseRecord.query.all()
    conflicts = [l for l in all_licenses if l.compatibility == "conflict"]
    compatible = [l for l in all_licenses if l.compatibility == "compatible"]

    license_summary = {}
    for lic in all_licenses:
        key = lic.spdx_id or lic.license_name
        if key not in license_summary:
            license_summary[key] = {"count": 0, "compatibility": lic.compatibility, "conflicts": 0}
        license_summary[key]["count"] += 1
        if lic.compatibility == "conflict":
            license_summary[key]["conflicts"] += 1

    apps = Application.query.all()

    return render_template(
        "licenses.html",
        conflicts=conflicts,
        compatible_count=len(compatible),
        conflict_count=len(conflicts),
        license_summary=license_summary,
        license_matrix=LICENSE_MATRIX,
        applications=apps,
        total_licenses=len(all_licenses),
    )
