from backend.utils.helpers import get_risk_level


class RiskScoreEngine:
    """
    Risk Score = CVSS Score + License Penalty + Maintenance Penalty + Dependency Depth Weight
    """

    DEPTH_WEIGHTS = {0: 0, 1: 2, 2: 5, 3: 8, 4: 12, 5: 15}

    def __init__(self, thresholds=None):
        self.thresholds = thresholds or {
            "low": 25,
            "medium": 50,
            "high": 75,
            "critical": 100,
        }

    def calculate_dependency_risk(self, cvss_score, license_penalty, maintenance_penalty, depth):
        depth_weight = self.DEPTH_WEIGHTS.get(min(depth, 5), 15)
        return round(cvss_score + license_penalty + maintenance_penalty + depth_weight, 2)

    def calculate_application_risk(self, dependency_risks):
        if not dependency_risks:
            return 0.0, "low"

        avg_risk = sum(dependency_risks) / len(dependency_risks)
        max_risk = max(dependency_risks)
        score = round((avg_risk * 0.6) + (max_risk * 0.4), 2)
        level = get_risk_level(score, self.thresholds)
        return score, level

    def aggregate_vulnerability_cvss(self, vulnerabilities):
        if not vulnerabilities:
            return 0.0
        return max(v.cvss_score for v in vulnerabilities)
