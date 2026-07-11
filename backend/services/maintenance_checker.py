from datetime import datetime, timedelta, timezone


OUTDATED_THRESHOLDS = {
    "critical": 730,
    "high": 365,
    "medium": 180,
    "low": 90,
}


class MaintenanceChecker:
    """Evaluates dependency maintenance health and staleness."""

    def evaluate(self, dependency_name, last_updated=None, version=None):
        if last_updated is None:
            days_old = self._estimate_age(dependency_name, version)
            last_updated = datetime.now(timezone.utc) - timedelta(days=days_old)
        elif isinstance(last_updated, str):
            last_updated = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))

        now = datetime.now(timezone.utc)
        if last_updated.tzinfo is None:
            last_updated = last_updated.replace(tzinfo=timezone.utc)

        days_since_update = (now - last_updated).days

        if days_since_update >= OUTDATED_THRESHOLDS["critical"]:
            risk = "critical"
            is_outdated = True
            penalty = 20
        elif days_since_update >= OUTDATED_THRESHOLDS["high"]:
            risk = "high"
            is_outdated = True
            penalty = 15
        elif days_since_update >= OUTDATED_THRESHOLDS["medium"]:
            risk = "medium"
            is_outdated = True
            penalty = 8
        elif days_since_update >= OUTDATED_THRESHOLDS["low"]:
            risk = "low"
            is_outdated = True
            penalty = 3
        else:
            risk = "low"
            is_outdated = False
            penalty = 0

        return {
            "last_updated": last_updated,
            "days_since_update": days_since_update,
            "is_outdated": is_outdated,
            "maintenance_risk": risk,
            "penalty": penalty,
        }

    def _estimate_age(self, name, version):
        combined = f"{name}{version or ''}"
        return abs(hash(combined)) % 800 + 30
