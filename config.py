import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # A deployment should set SECRET_KEY. The random fallback is safe for a
    # single-process demo and is never a predictable repository secret.
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'database.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    REPORTS_FOLDER = os.path.join(BASE_DIR, "reports")
    GRAPHS_FOLDER = os.path.join(BASE_DIR, "graphs")
    SAMPLE_DATA_FOLDER = os.path.join(BASE_DIR, "sample_data")

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {"json", "csv"}
    MAX_SBOM_COMPONENTS = int(os.environ.get("MAX_SBOM_COMPONENTS", "10000"))
    VULNERABILITY_DB_PATH = os.environ.get(
        "VULNERABILITY_DB_PATH", os.path.join(BASE_DIR, "original datasets", "vulnerability_db.json")
    )

    DEFAULT_ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    DEFAULT_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"

    RISK_THRESHOLDS = {
        "low": 25,
        "medium": 50,
        "high": 75,
        "critical": 100,
    }
