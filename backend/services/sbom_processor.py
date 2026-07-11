import os
from datetime import datetime, timezone

from backend import db
from backend.models import Application, Dependency, Vulnerability, LicenseRecord, Scan
from backend.services.sbom_parser import SBOMParser
from backend.services.vulnerability_scanner import VulnerabilityScanner
from backend.services.license_checker import LicenseChecker
from backend.services.maintenance_checker import MaintenanceChecker
from backend.services.risk_engine import RiskScoreEngine
from backend.services.dependency_graph import DependencyGraphBuilder


class SBOMProcessor:
    """Orchestrates full SBOM ingestion pipeline."""

    def __init__(self, app_config):
        self.parser = SBOMParser()
        self.scanner = VulnerabilityScanner()
        self.license_checker = LicenseChecker()
        self.maintenance_checker = MaintenanceChecker()
        self.risk_engine = RiskScoreEngine(app_config.get("RISK_THRESHOLDS"))
        self.graph_builder = DependencyGraphBuilder()

    def process_upload(self, filepath, file_format, application_name, owner, criticality, app_config):
        components = self.parser.parse(filepath, file_format)

        app = Application.query.filter_by(name=application_name).first()
        if not app:
            app = Application(
                name=application_name,
                owner=owner,
                business_criticality=criticality,
                description=f"Imported from SBOM upload",
            )
            db.session.add(app)
            db.session.flush()
        else:
            Dependency.query.filter_by(application_id=app.id).delete()
            db.session.flush()

        dep_objects = []
        name_to_id = {}

        for i, comp in enumerate(components):
            depth = 0 if not comp.get("parent") else 1
            maint = self.maintenance_checker.evaluate(comp["name"], version=comp.get("version"))
            lic_info = self.license_checker.check_license(comp.get("license", "Unknown"))

            dep = Dependency(
                application_id=app.id,
                name=comp["name"],
                version=comp.get("version", "0.0.0"),
                package_manager=comp.get("package_manager", "npm"),
                license_name=comp.get("license", "Unknown"),
                depth=depth,
                last_updated=maint["last_updated"],
                is_outdated=maint["is_outdated"],
                maintenance_risk=maint["maintenance_risk"],
            )
            db.session.add(dep)
            db.session.flush()
            dep_objects.append(dep)
            name_to_id[comp["name"]] = dep.id

            if comp.get("parent") and comp["parent"] in name_to_id:
                dep.parent_id = name_to_id[comp["parent"]]
                dep.depth = 1

            lic_record = LicenseRecord(
                dependency_id=dep.id,
                license_name=comp.get("license", "Unknown"),
                spdx_id=lic_info["spdx_id"],
                compatibility=lic_info["compatibility"],
                conflict_with=lic_info["conflict_with"],
            )
            db.session.add(lic_record)

            vulns = self.scanner.scan_dependency(comp["name"], comp.get("version"))
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

            dep.risk_contribution = self.risk_engine.calculate_dependency_risk(
                max_cvss, lic_info["penalty"], maint["penalty"], dep.depth
            )

        dep_risks = [d.risk_contribution for d in dep_objects]
        app.risk_score, app.risk_level = self.risk_engine.calculate_application_risk(dep_risks)
        app.updated_at = datetime.now(timezone.utc)

        vuln_count = sum(len(list(d.vulnerabilities)) for d in dep_objects)
        scan = Scan(
            application_id=app.id,
            filename=os.path.basename(filepath),
            format=file_format,
            status="completed",
            risk_score=app.risk_score,
            dependency_count=len(dep_objects),
            vulnerability_count=vuln_count,
        )
        db.session.add(scan)
        db.session.commit()

        self.graph_builder.generate_graph_image(app.id, app_config["GRAPHS_FOLDER"])

        return app, scan
