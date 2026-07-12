import os
from collections import deque
from datetime import datetime, timezone

from backend import db
from backend.models import Application, Dependency, Vulnerability, LicenseRecord, Scan
from backend.services.sbom_parser import SBOMParser
from backend.services.vulnerability_scanner import VulnerabilityScanner
from backend.services.license_checker import LicenseChecker
from backend.services.maintenance_checker import MaintenanceChecker
from backend.services.risk_engine import RiskScoreEngine
from backend.services.dependency_graph import DependencyGraphBuilder
from backend.services.vulnerability_chain_analyzer import VulnerabilityChainAnalyzer


class SBOMProcessor:
    """Orchestrates full SBOM ingestion pipeline."""

    def __init__(self, app_config):
        self.parser = SBOMParser()
        self.scanner = VulnerabilityScanner(database_path=app_config.get("VULNERABILITY_DB_PATH"))
        self.license_checker = LicenseChecker()
        self.maintenance_checker = MaintenanceChecker()
        self.risk_engine = RiskScoreEngine(app_config.get("RISK_THRESHOLDS"))
        self.graph_builder = DependencyGraphBuilder()
        # Step 4: reused as-is from Step 2 - no duplicate graph traversal logic.
        self.chain_analyzer = VulnerabilityChainAnalyzer()

    def process_upload(self, filepath, file_format, application_name, owner, criticality, app_config):
        components = self.parser.parse(filepath, file_format)
        if not components:
            raise ValueError("The SBOM contains no components")
        max_components = app_config.get("MAX_SBOM_COMPONENTS", 10000)
        if len(components) > max_components:
            raise ValueError(f"The SBOM has too many components (maximum: {max_components})")

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
            # ORM deletes preserve cascade behaviour for child findings.
            # The caller rolls back this replacement if a later stage fails.
            for old_dependency in app.dependencies.all():
                db.session.delete(old_dependency)
            db.session.flush()

        dep_objects = []
        # Maps the parser's component_id (bom-ref for CycloneDX, name for
        # flat JSON/CSV/generic formats) to the created Dependency's DB id.
        # Using component_id instead of raw name lets the same package name
        # appear safely at multiple positions/versions in a CycloneDX SBOM.
        component_id_to_dep_id = {}
        # Per-dependency inputs needed later for risk calculation, once the
        # true graph depth is known (pass 3/4 below).
        risk_inputs = {}

        # --- Pass 1: create all Dependency rows + their license/vulnerability
        # records. Depth and parent_id are NOT resolved here, because a
        # component's parent may appear later in the list (or not at all, in
        # the case of forward references in the SBOM's dependency graph).
        for comp in components:
            maint = self.maintenance_checker.evaluate(comp["name"], version=comp.get("version"))
            lic_info = self.license_checker.check_license(comp.get("license", "Unknown"))

            dep = Dependency(
                application_id=app.id,
                name=comp["name"],
                version=comp.get("version", "0.0.0"),
                package_manager=comp.get("package_manager", "npm"),
                license_name=comp.get("license", "Unknown"),
                depth=0,  # placeholder, corrected in pass 3 below
                last_updated=maint["last_updated"],
                is_outdated=maint["is_outdated"],
                maintenance_risk=maint["maintenance_risk"],
            )
            db.session.add(dep)
            db.session.flush()
            dep_objects.append(dep)
            component_id_to_dep_id[comp["component_id"]] = dep.id

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

            risk_inputs[dep.id] = {
                "max_cvss": max_cvss,
                "license_penalty": lic_info["penalty"],
                "maintenance_penalty": maint["penalty"],
                "parent_component_id": comp.get("parent"),
            }

        # --- Pass 2: resolve parent_id links now that every component_id in
        # this SBOM is known, regardless of the order components appeared in.
        for dep in dep_objects:
            parent_component_id = risk_inputs[dep.id]["parent_component_id"]
            if parent_component_id and parent_component_id in component_id_to_dep_id:
                parent_dep_id = component_id_to_dep_id[parent_component_id]
                if parent_dep_id != dep.id:  # guard against a self-referencing edge
                    dep.parent_id = parent_dep_id

        # --- Pass 3: compute the REAL depth of every dependency by walking
        # the resolved parent/child graph breadth-first from the roots
        # (components with no resolvable parent). This replaces the old
        # logic that only ever produced depth 0 or depth 1, and now supports
        # dependency chains of arbitrary length (root -> dep -> transitive
        # dep -> transitive-of-transitive dep -> ...).
        children_by_parent_id = {}
        for dep in dep_objects:
            if dep.parent_id is not None:
                children_by_parent_id.setdefault(dep.parent_id, []).append(dep)

        roots = [dep for dep in dep_objects if dep.parent_id is None]
        visited_ids = set()
        queue = deque((root, 0) for root in roots)
        while queue:
            current, depth = queue.popleft()
            if current.id in visited_ids:
                # Already assigned via another path (e.g. a malformed/cyclic
                # SBOM). Skip to avoid infinite loops instead of crashing.
                continue
            visited_ids.add(current.id)
            current.depth = depth
            for child in children_by_parent_id.get(current.id, []):
                queue.append((child, depth + 1))

        # Any dependency not reached by the BFS (e.g. part of a cycle that
        # never connects back to a true root) safely falls back to depth 0
        # rather than being left unset. TODO: surface a warning in the scan
        # result if this ever occurs, so malformed SBOMs are visible to users.

        # --- Pass 4: now that every dependency's true depth is known,
        # calculate its risk contribution (depth affects the risk weight).
        for dep in dep_objects:
            inputs = risk_inputs[dep.id]
            dep.risk_contribution = self.risk_engine.calculate_dependency_risk(
                inputs["max_cvss"], inputs["license_penalty"], inputs["maintenance_penalty"], dep.depth
            )

        dep_risks = [d.risk_contribution for d in dep_objects]

        # --- Pass 5 (Step 4): fold vulnerability-chain PROPAGATION signals
        # into the application's composite risk score. Reuses Step 2's
        # VulnerabilityChainAnalyzer unmodified - no duplicate graph
        # traversal logic. By this point every Dependency's parent_id/depth
        # (Pass 2/3) and every Vulnerability row (Pass 1) are already
        # pending in this session; SQLAlchemy's autoflush makes them visible
        # to the analyzer's queries even though nothing has been committed
        # yet, so no extra flush call is needed here.
        chain_summary = self.chain_analyzer.summarize_application_exposure(app.id)
        app.risk_score, app.risk_level = self.risk_engine.calculate_composite_application_risk(
            dep_risks, chain_summary
        )
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
