import secrets
from functools import wraps

from flask import abort, request, session, redirect, url_for, flash


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function


def csrf_token():
    """Create and return the current session's anti-forgery token."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return f(*args, **kwargs)
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not submitted or not secrets.compare_digest(submitted, expected):
            abort(400, description="Your form expired. Refresh the page and try again.")
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
