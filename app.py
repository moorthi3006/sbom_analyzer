import os

from flask import Flask, send_from_directory, render_template
from config import Config
from backend import db


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(config_class)
    from backend.utils.helpers import csrf_token
    app.jinja_env.globals["csrf_token"] = csrf_token

    for folder_key in (
        "UPLOAD_FOLDER",
        "REPORTS_FOLDER",
        "GRAPHS_FOLDER",
        "SAMPLE_DATA_FOLDER",
    ):
        os.makedirs(app.config[folder_key], exist_ok=True)

    db.init_app(app)

    from backend.routes.auth import auth_bp
    from backend.routes.dashboard import dashboard_bp
    from backend.routes.upload import upload_bp
    from backend.routes.applications import applications_bp
    from backend.routes.dependencies import dependencies_bp
    from backend.routes.vulnerabilities import vulnerabilities_bp
    from backend.routes.licenses import licenses_bp
    from backend.routes.maintenance import maintenance_bp
    from backend.routes.reports import reports_bp
    from backend.routes.settings import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(applications_bp)
    app.register_blueprint(dependencies_bp)
    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(licenses_bp)
    app.register_blueprint(maintenance_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)

    @app.route("/graphs/<path:filename>")
    def serve_graph(filename):
        return send_from_directory(app.config["GRAPHS_FOLDER"], filename)

    with app.app_context():
        from backend.models import (
            User,
            Application,
            Dependency,
            Vulnerability,
            LicenseRecord,
            Scan,
            Report,
        )

        db.create_all()

        # Bootstrap is opt-in: the repository never ships usable credentials.
        if User.query.count() == 0:
            admin_password = app.config.get("DEFAULT_ADMIN_PASSWORD")
            if admin_password:
                admin = User(
                    username=app.config["DEFAULT_ADMIN_USERNAME"],
                    email=os.environ.get("ADMIN_EMAIL", "admin@sbom.local"),
                    role="Administrator",
                )
                admin.set_password(admin_password)
                db.session.add(admin)
                db.session.commit()
            else:
                app.logger.warning("No admin created. Set ADMIN_PASSWORD before the first startup.")

    @app.errorhandler(413)
    def file_too_large(_error):
        return render_template("upload.html"), 413

    return app


if __name__ == "__main__":
    application = create_app()

    print("=" * 60)
    print("SBOM Analyzer")
    print("Running at http://127.0.0.1:5000")
    print("Set ADMIN_PASSWORD (and preferably SECRET_KEY) before first startup.")
    print("=" * 60)

    application.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
