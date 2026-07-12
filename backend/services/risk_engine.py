from backend.utils.helpers import get_risk_level


class RiskScoreEngine:
    """
    Base dependency-level formula (UNCHANGED since Step 1):
        Risk Score = CVSS Score + License Penalty + Maintenance Penalty + Dependency Depth Weight

    Step 4 adds a COMPOSITE application-level formula on top of the existing
    base application score (see calculate_composite_application_risk below),
    folding in vulnerability-PROPAGATION signals from the transitive
    dependency graph (Step 2's VulnerabilityChainAnalyzer): how many
    distinct vulnerable chains exist, how deep the worst one runs, and the
    highest CVSS reachable transitively. calculate_application_risk() itself
    is untouched - the new method calls it internally rather than
    duplicating its logic.
    """

    DEPTH_WEIGHTS = {0: 0, 1: 2, 2: 5, 3: 8, 4: 12, 5: 15}

    # --- Step 4: weights for the chain-propagation terms, layered on top of
    # the existing base score. Each term is capped so that a pathological
    # SBOM (e.g. hundreds of chains) cannot make the score explode - it can
    # only push the application toward "critical", not off the scale.
    CHAIN_COUNT_WEIGHT = 3      # points added per distinct vulnerable chain
    CHAIN_COUNT_CAP = 15        # ceiling on the chain-count contribution
    CHAIN_CVSS_WEIGHT = 1.5     # multiplier on the worst CVSS reachable via any chain
    CHAIN_CVSS_CAP = 15         # ceiling on the chain-cvss contribution

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
        """
        Base application risk from per-dependency risk contributions only.
        UNCHANGED from Step 1-3: existing callers keep getting exactly the
        same result. calculate_composite_application_risk() below extends
        this rather than replacing it.
        """
        if not dependency_risks:
            return 0.0, "low"

        avg_risk = sum(dependency_risks) / len(dependency_risks)
        max_risk = max(dependency_risks)
        score = round((avg_risk * 0.6) + (max_risk * 0.4), 2)
        level = get_risk_level(score, self.thresholds)
        return score, level

    def calculate_composite_application_risk(self, dependency_risks, chain_summary=None):
        """
        Step 4: extends calculate_application_risk() with vulnerability
        PROPAGATION signals from the transitive dependency graph, instead of
        scoring each dependency in isolation.

        `chain_summary` is expected to be the dict shape returned by
        VulnerabilityChainAnalyzer.summarize_application_exposure():
            { "vulnerable_chain_count": int,
              "max_chain_depth": int,
              "max_cvss_in_chain": float,
              "chains": [...] }

        Formula:
            composite = base_score
                        + chain_count_component   (min(count * 3, 15))
                        + chain_depth_component    (DEPTH_WEIGHTS[max_depth])
                        + chain_cvss_component      (min(max_cvss * 1.5, 15))

        If chain_summary is missing or reports zero vulnerable chains, this
        method returns EXACTLY what calculate_application_risk() would have
        returned - full backward compatibility with Step 1-3 behavior for
        any application with no detected vulnerability propagation.
        """
        base_score, _ = self.calculate_application_risk(dependency_risks)

        chain_count = (chain_summary or {}).get("vulnerable_chain_count", 0)
        if not chain_count:
            # No propagation signal to add - identical to the base score.
            level = get_risk_level(base_score, self.thresholds)
            return round(base_score, 2), level

        max_depth = chain_summary.get("max_chain_depth", 0)
        max_cvss = chain_summary.get("max_cvss_in_chain", 0.0)

        chain_count_component = min(chain_count * self.CHAIN_COUNT_WEIGHT, self.CHAIN_COUNT_CAP)
        chain_depth_component = self.DEPTH_WEIGHTS.get(min(max_depth, 5), 15)
        chain_cvss_component = min(max_cvss * self.CHAIN_CVSS_WEIGHT, self.CHAIN_CVSS_CAP)

        composite_score = round(
            base_score + chain_count_component + chain_depth_component + chain_cvss_component, 2
        )
        level = get_risk_level(composite_score, self.thresholds)
        return composite_score, level

    def aggregate_vulnerability_cvss(self, vulnerabilities):
        if not vulnerabilities:
            return 0.0
        return max(v.cvss_score for v in vulnerabilities)
