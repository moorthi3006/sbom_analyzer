from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app

from backend import db
from backend.models import User
from backend.utils.helpers import csrf_protect, login_required

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("/", methods=["GET", "POST"])
@login_required
@csrf_protect
def index():
    user = User.query.get(session["user_id"])

    if request.method == "POST":
        action = request.form.get("action")

        if action == "update_profile":
            email = request.form.get("email", "").strip()
            if email:
                user.email = email
                db.session.commit()
                flash("Profile updated successfully.", "success")

        elif action == "change_password":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not user.check_password(current_password):
                flash("Current password is incorrect.", "danger")
            elif new_password != confirm_password:
                flash("New passwords do not match.", "danger")
            elif len(new_password) < 6:
                flash("Password must be at least 6 characters.", "danger")
            else:
                user.set_password(new_password)
                db.session.commit()
                flash("Password changed successfully.", "success")

        return redirect(url_for("settings.index"))

    return render_template(
        "settings.html",
        user=user,
        config=current_app.config,
    )
