import json
import random
from datetime import datetime, timedelta, timezone

from flask import current_app

from backend import db
from backend.models import User, Application, Dependency, Vulnerability, LicenseRecord, Scan, Report
from backend.services.vulnerability_scanner import VulnerabilityScanner
from backend.services.license_checker import LicenseChecker
from backend.services.maintenance_checker import MaintenanceChecker
from backend.services.risk_engine import RiskScoreEngine


APPLICATIONS = [
    ("Payment Gateway API", "Core payment processing microservice", "Sarah Chen", "critical"),
    ("Customer Portal", "Self-service customer management portal", "James Wilson", "high"),
    ("Inventory Management", "Warehouse and stock tracking system", "Maria Garcia", "high"),
    ("Analytics Dashboard", "Business intelligence and reporting", "David Kim", "medium"),
    ("Mobile Banking App", "iOS and Android banking client", "Lisa Thompson", "critical"),
    ("HR Management System", "Employee records and payroll", "Robert Brown", "medium"),
    ("E-Commerce Platform", "Online retail storefront", "Emily Davis", "high"),
    ("DevOps Pipeline", "CI/CD automation infrastructure", "Alex Martinez", "high"),
    ("Identity Provider", "SSO and authentication service", "Jennifer Lee", "critical"),
    ("Notification Service", "Email, SMS, and push notifications", "Michael Taylor", "medium"),
]

PACKAGE_NAMES = [
    "lodash", "express", "react", "axios", "moment", "webpack", "babel-core",
    "typescript", "eslint", "prettier", "jest", "mocha", "chai", "sinon",
    "request", "urllib3", "flask", "django", "numpy", "pandas", "requests",
    "cryptography", "pillow", "sqlalchemy", "celery", "redis", "pymongo",
    "boto3", "kubernetes", "docker", "terraform", "ansible", "jwt-decode",
    "jsonwebtoken", "bcrypt", "passport", "mongoose", "sequelize", "knex",
    "pg", "mysql2", "sqlite3", "dotenv", "winston", "pino", "helmet",
    "cors", "compression", "body-parser", "multer", "sharp", "nodemailer",
    "socket.io", "ws", "grpc", "protobuf", "yaml", "toml", "ini",
    "semver", "chalk", "commander", "yargs", "inquirer", "ora", "debug",
    "async", "bluebird", "rxjs", "zone.js", "angular", "vue", "svelte",
    "next", "nuxt", "gatsby", "vite", "rollup", "esbuild", "swc",
    "tailwindcss", "bootstrap", "material-ui", "antd", "chakra-ui",
    "storybook", "cypress", "playwright", "puppeteer", "selenium",
    "opencv", "tensorflow", "pytorch", "scikit-learn", "matplotlib",
    "seaborn", "plotly", "d3", "chart.js", "highcharts", "ag-grid",
    "spring-boot", "hibernate", "jackson", "guava", "okhttp", "retrofit",
    "slf4j", "log4j", "junit", "mockito", "gradle", "maven", "ant",
]

LICENSES = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "GPL-3.0", "LGPL-3.0", "MPL-2.0", "Proprietary", "Unknown"]
PACKAGE_MANAGERS = ["npm", "pip", "maven", "gradle", "go", "cargo", "nuget"]


def initialize_database():
    if User.query.first():
        return

    admin = User(username="admin", email="admin@sbom-analyzer.local", role="admin")
    admin.set_password(current_app.config.get("DEFAULT_ADMIN_PASSWORD", "admin123"))
    db.session.add(admin)

    scanner = VulnerabilityScanner()
    license_checker = LicenseChecker()
    maintenance_checker = MaintenanceChecker()
    risk_engine = RiskScoreEngine(current_app.config.get("RISK_THRESHOLDS"))

    all_deps_for_cves = []
    dep_counter = 0

    for app_name, desc, owner, criticality in APPLICATIONS:
        app = Application(
            name=app_name,
            description=desc,
            owner=owner,
            business_criticality=criticality,
        )
        db.session.add(app)
        db.session.flush()

        num_deps = random.randint(40, 60)
        app_deps = []
        root_deps = []

        for i in range(num_deps):
            pkg = PACKAGE_NAMES[dep_counter % len(PACKAGE_NAMES)]
            dep_counter += 1
            version = f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(0, 30)}"
            license_name = random.choice(LICENSES)
            depth = 0 if i < 8 else random.randint(1, 4)
            parent_id = None
            if depth > 0 and root_deps:
                parent = random.choice(root_deps if depth == 1 else app_deps)
                parent_id = parent.id if hasattr(parent, 'id') and parent.id else None

            maint = maintenance_checker.evaluate(pkg, version=version)
            lic_info = license_checker.check_license(license_name)

            dep = Dependency(
                application_id=app.id,
                name=pkg,
                version=version,
                package_manager=random.choice(PACKAGE_MANAGERS),
                license_name=license_name,
                depth=depth,
                last_updated=maint["last_updated"],
                is_outdated=maint["is_outdated"],
                maintenance_risk=maint["maintenance_risk"],
            )
            db.session.add(dep)
            db.session.flush()

            if depth == 0:
                root_deps.append(dep)
            app_deps.append(dep)

            if parent_id:
                dep.parent_id = parent_id

            lic_record = LicenseRecord(
                dependency_id=dep.id,
                license_name=license_name,
                spdx_id=lic_info["spdx_id"],
                compatibility=lic_info["compatibility"],
                conflict_with=lic_info["conflict_with"],
            )
            db.session.add(lic_record)

            vulns = scanner.scan_dependency(pkg, version)
            max_cvss = 0
            for vuln_data in vulns:
                max_cvss = max(max_cvss, vuln_data["cvss_score"])
                vuln = Vulnerability(
                    dependency_id=dep.id,
                    cve_id=vuln_data["cve_id"],
                    severity=vuln_data["severity"],
                    cvss_score=vuln_data["cvss_score"],
                    description=vuln_data["description"],
                    patch_available=vuln_data["patch_available"],
                    published_date=vuln_data["published_date"],
                )
                db.session.add(vuln)
                all_deps_for_cves.append(vuln)

            dep.risk_contribution = risk_engine.calculate_dependency_risk(
                max_cvss, lic_info["penalty"], maint["penalty"], depth
            )

        dep_risks = [d.risk_contribution for d in app_deps]
        app.risk_score, app.risk_level = risk_engine.calculate_application_risk(dep_risks)

        scan = Scan(
            application_id=app.id,
            filename=f"{app_name.replace(' ', '_').lower()}_sbom.json",
            format="json",
            status="completed",
            risk_score=app.risk_score,
            dependency_count=len(app_deps),
            vulnerability_count=sum(d.vulnerabilities.count() for d in app_deps),
            created_at=datetime.now(timezone.utc) - timedelta(days=random.randint(1, 60)),
        )
        db.session.add(scan)

    _ensure_minimum_cves(scanner, dep_counter)
    _create_sample_data_files()
    db.session.commit()


def _ensure_minimum_cves(scanner, dep_counter):
    existing_cve_count = Vulnerability.query.count()
    if existing_cve_count >= 200:
        return

    deps_without_many_vulns = Dependency.query.limit(200).all()
    cve_num = existing_cve_count + 1
    templates = [
        ("critical", 9.0, 10.0),
        ("high", 7.0, 8.9),
        ("medium", 4.0, 6.9),
        ("low", 1.0, 3.9),
    ]

    for dep in deps_without_many_vulns:
        if Vulnerability.query.count() >= 200:
            break
        if dep.vulnerabilities.count() > 2:
            continue

        for _ in range(random.randint(1, 3)):
            if Vulnerability.query.count() >= 200:
                break
            sev, lo, hi = random.choice(templates)
            year = random.choice([2019, 2020, 2021, 2022, 2023, 2024, 2025])
            cve_id = f"CVE-{year}-{cve_num:04d}"
            cve_num += 1
            vuln = Vulnerability(
                dependency_id=dep.id,
                cve_id=cve_id,
                severity=sev,
                cvss_score=round(random.uniform(lo, hi), 1),
                description=f"Security vulnerability in {dep.name} version {dep.version}",
                patch_available=random.choice([True, True, False]),
                published_date=datetime.now(timezone.utc) - timedelta(days=random.randint(30, 1000)),
            )
            db.session.add(vuln)


def _create_sample_data_files():
    sample_dir = current_app.config["SAMPLE_DATA_FOLDER"]

    sample_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"type": "library", "name": "express", "version": "4.18.2", "licenses": [{"license": {"id": "MIT"}}]},
            {"type": "library", "name": "lodash", "version": "4.17.21", "licenses": [{"license": {"id": "MIT"}}]},
            {"type": "library", "name": "axios", "version": "1.6.0", "licenses": [{"license": {"id": "MIT"}}]},
            {"type": "library", "name": "jsonwebtoken", "version": "9.0.0", "licenses": [{"license": {"id": "MIT"}}]},
            {"type": "library", "name": "helmet", "version": "7.1.0", "licenses": [{"license": {"id": "MIT"}}]},
        ],
    }
    with open(f"{sample_dir}/sample_sbom.json", "w", encoding="utf-8") as f:
        json.dump(sample_sbom, f, indent=2)

    import csv
    with open(f"{sample_dir}/sample_sbom.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "version", "package_manager", "license", "parent"])
        writer.writerow(["flask", "3.0.3", "pip", "BSD-3-Clause", ""])
        writer.writerow(["sqlalchemy", "2.0.36", "pip", "MIT", "flask"])
        writer.writerow(["werkzeug", "3.0.6", "pip", "BSD-3-Clause", "flask"])
        writer.writerow(["requests", "2.31.0", "pip", "Apache-2.0", ""])
        writer.writerow(["urllib3", "2.1.0", "pip", "MIT", "requests"])

    license_matrix = {
        "project_license": "Apache-2.0",
        "licenses": {
            lic: {"compatible_with": info["compatible"], "risk_penalty": info["risk"]}
            for lic, info in __import__("backend.services.license_checker", fromlist=["LICENSE_MATRIX"]).LICENSE_MATRIX.items()
        },
    }
    with open(f"{sample_dir}/license_matrix.json", "w", encoding="utf-8") as f:
        json.dump(license_matrix, f, indent=2)
