LICENSE_MATRIX = {
    "MIT": {"compatible": ["Apache-2.0", "BSD-3-Clause", "ISC", "MIT"], "risk": 0},
    "Apache-2.0": {"compatible": ["MIT", "BSD-3-Clause", "ISC", "Apache-2.0"], "risk": 0},
    "BSD-3-Clause": {"compatible": ["MIT", "Apache-2.0", "ISC", "BSD-3-Clause"], "risk": 0},
    "ISC": {"compatible": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"], "risk": 0},
    "GPL-3.0": {"compatible": ["GPL-3.0", "AGPL-3.0"], "risk": 15},
    "GPL-2.0": {"compatible": ["GPL-2.0", "GPL-3.0"], "risk": 12},
    "AGPL-3.0": {"compatible": ["AGPL-3.0", "GPL-3.0"], "risk": 20},
    "LGPL-3.0": {"compatible": ["LGPL-3.0", "GPL-3.0"], "risk": 8},
    "MPL-2.0": {"compatible": ["MPL-2.0", "Apache-2.0"], "risk": 5},
    "Unlicense": {"compatible": ["MIT", "Unlicense", "CC0-1.0"], "risk": 2},
    "CC0-1.0": {"compatible": ["MIT", "Unlicense", "CC0-1.0"], "risk": 1},
    "Proprietary": {"compatible": ["Proprietary"], "risk": 25},
    "Unknown": {"compatible": [], "risk": 10},
}


class LicenseChecker:
    """Checks license compatibility and identifies conflicts."""

    def __init__(self, project_license="Apache-2.0"):
        self.project_license = project_license
        self.matrix = LICENSE_MATRIX

    def check_license(self, license_name):
        normalized = self._normalize(license_name)
        info = self.matrix.get(normalized, self.matrix["Unknown"])

        if normalized == self.project_license or normalized in info["compatible"]:
            compatibility = "compatible"
            conflict = None
        elif self.project_license in info.get("compatible", []):
            compatibility = "compatible"
            conflict = None
        else:
            compatibility = "conflict"
            conflict = f"{normalized} conflicts with project license {self.project_license}"

        return {
            "license_name": license_name,
            "spdx_id": normalized,
            "compatibility": compatibility,
            "conflict_with": conflict,
            "penalty": info["risk"],
        }

    def check_all(self, dependencies):
        results = []
        seen = set()
        for dep in dependencies:
            lic = dep.get("license") if isinstance(dep, dict) else dep.license_name
            if not lic or lic in seen:
                continue
            seen.add(lic)
            results.append(self.check_license(lic))
        return results

    def find_conflicts(self, dependencies):
        return [r for r in self.check_all(dependencies) if r["compatibility"] == "conflict"]

    def _normalize(self, license_name):
        if not license_name:
            return "Unknown"
        name = license_name.strip()
        aliases = {
            "Apache License 2.0": "Apache-2.0",
            "MIT License": "MIT",
            "BSD": "BSD-3-Clause",
            "GPL": "GPL-3.0",
            "GPLv3": "GPL-3.0",
        }
        return aliases.get(name, name)
