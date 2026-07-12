from functools import wraps

from flask import session, redirect, url_for, flash


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename, allowed_extensions):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def get_risk_level(score, thresholds):
    if score >= thresholds["high"]:
        return "critical" if score >= thresholds["critical"] else "high"
    if score >= thresholds["medium"]:
        return "medium"
    return "low"


def risk_badge_class(level):
    mapping = {
        "low": "bg-success",
        "medium": "bg-warning text-dark",
        "high": "bg-danger",
        "critical": "bg-dark",
    }
    return mapping.get(level, "bg-secondary")


def severity_badge_class(severity):
    mapping = {
        "critical": "bg-dark",
        "high": "bg-danger",
        "medium": "bg-warning text-dark",
        "low": "bg-info text-dark",
    }
    return mapping.get(severity.lower(), "bg-secondary")
