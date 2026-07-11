from backend.models import Application, Dependency, Vulnerability, Scan, Report
from backend import db


class DashboardAnalytics:
    """Provides aggregated analytics data for the dashboard."""

    def get_summary_cards(self):
        total_apps = Application.query.count()
        total_deps = Dependency.query.count()
        total_vulns = Vulnerability.query.count()
        critical_vulns = Vulnerability.query.filter_by(severity="critical").count()
        high_risk_apps = Application.query.filter(
            Application.risk_level.in_(["high", "critical"])
        ).count()
        avg_risk = db.session.query(db.func.avg(Application.risk_score)).scalar() or 0

        return {
            "total_applications": total_apps,
            "total_dependencies": total_deps,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "high_risk_applications": high_risk_apps,
            "average_risk_score": round(avg_risk, 1),
        }

    def get_risk_distribution(self):
        levels = ["low", "medium", "high", "critical"]
        distribution = {}
        for level in levels:
            distribution[level] = Application.query.filter_by(risk_level=level).count()
        return distribution

    def get_severity_distribution(self):
        severities = ["critical", "high", "medium", "low"]
        distribution = {}
        for sev in severities:
            distribution[sev] = Vulnerability.query.filter_by(severity=sev).count()
        return distribution

    def get_recent_scans(self, limit=8):
        return Scan.query.order_by(Scan.created_at.desc()).limit(limit).all()

    def get_recent_vulnerabilities(self, limit=8):
        return Vulnerability.query.order_by(Vulnerability.cvss_score.desc()).limit(limit).all()

    def get_recent_reports(self, limit=5):
        return Report.query.order_by(Report.generated_at.desc()).limit(limit).all()

    def get_top_risk_applications(self, limit=5):
        return Application.query.order_by(Application.risk_score.desc()).limit(limit).all()

    def get_license_conflict_count(self):
        from backend.models import LicenseRecord
        return LicenseRecord.query.filter_by(compatibility="conflict").count()

    def get_outdated_count(self):
        return Dependency.query.filter_by(is_outdated=True).count()

    def get_scan_trend(self):
        scans = Scan.query.order_by(Scan.created_at.asc()).limit(12).all()
        labels = []
        scores = []
        for scan in scans:
            labels.append(scan.created_at.strftime("%m/%d"))
            scores.append(scan.risk_score)
        return {"labels": labels, "scores": scores}
