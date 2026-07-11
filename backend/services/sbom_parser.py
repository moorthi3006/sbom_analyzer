import csv
import json
from datetime import datetime, timezone


class SBOMParser:
    """Parses SBOM files in JSON (CycloneDX) and CSV formats."""

    def parse(self, filepath, file_format):
        if file_format == "json":
            return self._parse_json(filepath)
        if file_format == "csv":
            return self._parse_csv(filepath)
        raise ValueError(f"Unsupported SBOM format: {file_format}")

    def _parse_json(self, filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        components = []
        if "components" in data:
            for comp in data["components"]:
                components.append({
                    "name": comp.get("name", "unknown"),
                    "version": comp.get("version", "0.0.0"),
                    "package_manager": comp.get("type", "library"),
                    "license": self._extract_license(comp),
                    "parent": comp.get("group"),
                })
        elif "bomFormat" not in data and isinstance(data, list):
            for comp in data:
                components.append({
                    "name": comp.get("name", "unknown"),
                    "version": comp.get("version", "0.0.0"),
                    "package_manager": comp.get("package_manager", "npm"),
                    "license": comp.get("license", "Unknown"),
                    "parent": comp.get("parent"),
                })
        else:
            for comp in data.get("dependencies", []):
                components.append({
                    "name": comp.get("name", "unknown"),
                    "version": comp.get("version", "0.0.0"),
                    "package_manager": comp.get("package_manager", "npm"),
                    "license": comp.get("license", "Unknown"),
                    "parent": comp.get("parent"),
                })

        return components

    def _parse_csv(self, filepath):
        components = []
        with open(filepath, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                components.append({
                    "name": row.get("name", row.get("package", "unknown")),
                    "version": row.get("version", "0.0.0"),
                    "package_manager": row.get("package_manager", row.get("type", "npm")),
                    "license": row.get("license", "Unknown"),
                    "parent": row.get("parent"),
                })
        return components

    def _extract_license(self, component):
        licenses = component.get("licenses", [])
        if licenses:
            lic = licenses[0]
            if "license" in lic:
                return lic["license"].get("id", lic["license"].get("name", "Unknown"))
            return lic.get("id", lic.get("name", "Unknown"))
        return component.get("license", "Unknown")
