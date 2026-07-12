from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash

from backend import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), default="admin")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Application(db.Model):
    __tablename__ = "applications"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    owner = db.Column(db.String(100), nullable=False)
    business_criticality = db.Column(db.String(50), default="medium")
    risk_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(20), default="low")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    dependencies = db.relationship("Dependency", backref="application", lazy="dynamic", cascade="all, delete-orphan")
    scans = db.relationship("Scan", backref="application", lazy="dynamic", cascade="all, delete-orphan")
    reports = db.relationship("Report", backref="application", lazy="dynamic", cascade="all, delete-orphan")

    @property
    def status(self):
        latest_scan = self.scans.order_by(Scan.created_at.desc()).first()
        return latest_scan.status if latest_scan else "no scans"


class Dependency(db.Model):
    __tablename__ = "dependencies"

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    version = db.Column(db.String(50))
    package_manager = db.Column(db.String(50), default="npm")
    license_name = db.Column(db.String(100))
    depth = db.Column(db.Integer, default=0)
    parent_id = db.Column(db.Integer, db.ForeignKey("dependencies.id"), nullable=True)
    last_updated = db.Column(db.DateTime)
    is_outdated = db.Column(db.Boolean, default=False)
    maintenance_risk = db.Column(db.String(20), default="low")
    risk_contribution = db.Column(db.Float, default=0.0)

    parent = db.relationship("Dependency", remote_side=[id], backref="children")
    vulnerabilities = db.relationship("Vulnerability", backref="dependency", lazy="dynamic", cascade="all, delete-orphan")
    license_records = db.relationship("LicenseRecord", backref="dependency", lazy="dynamic", cascade="all, delete-orphan")


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    dependency_id = db.Column(db.Integer, db.ForeignKey("dependencies.id"), nullable=False)
    cve_id = db.Column(db.String(30), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    cvss_score = db.Column(db.Float, default=0.0)
    description = db.Column(db.Text)
    patch_available = db.Column(db.Boolean, default=False)
    published_date = db.Column(db.DateTime)


class LicenseRecord(db.Model):
    __tablename__ = "license_records"

    id = db.Column(db.Integer, primary_key=True)
    dependency_id = db.Column(db.Integer, db.ForeignKey("dependencies.id"), nullable=False)
    license_name = db.Column(db.String(100), nullable=False)
    spdx_id = db.Column(db.String(50))
    compatibility = db.Column(db.String(50), default="compatible")
    conflict_with = db.Column(db.String(200))


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    filename = db.Column(db.String(255))
    format = db.Column(db.String(10))
    status = db.Column(db.String(30), default="completed")
    risk_score = db.Column(db.Float, default=0.0)
    dependency_count = db.Column(db.Integer, default=0)
    vulnerability_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    generated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    scan = db.relationship("Scan", backref="reports")
