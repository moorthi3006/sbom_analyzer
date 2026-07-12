import hashlib
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

    @staticmethod
    def _stable_seed(key):
        """
        Derives a stable integer seed from `key` using SHA-256, instead of
        Python's built-in `hash()`, which is intentionally randomized per
        process (PYTHONHASHSEED) since Python 3.3 as a security hardening
        measure and therefore unsuitable for anything that must reproduce
        the same result across restarts. Same technique used in Step 3's
        vulnerability_scanner.py, for consistency.
        """
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return int(digest[:16], 16)  # 64 bits of the digest - plenty of entropy

    def _estimate_age(self, name, version):
        """
        Deterministically estimates an age (in days) for a dependency that
        has no real `last_updated` date supplied by the SBOM. Same formula
        and output RANGE (30-829 days) as before - only the source of the
        number changed, from Python's randomized `hash()` to a stable
        SHA-256-derived seed, so the same (name, version) always produces
        the same estimated age, on every machine, every restart.
        """
        combined = f"{name}{version or ''}"
        return self._stable_seed(combined) % 800 + 30
