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

        if "components" in data:
            return self._parse_cyclonedx(data)
        elif "bomFormat" not in data and isinstance(data, list):
            return self._parse_flat_list(data)
        else:
            return self._parse_generic_dependencies(data)

    def _parse_cyclonedx(self, data):
        """
        Parses a CycloneDX SBOM, resolving TRUE transitive dependency chains.

        CycloneDX does not encode parent/child relationships on the component
        itself. `group` is a namespace (e.g. "@babel"), not a dependency edge,
        so it must never be used as a parent. The real relationship graph
        lives in the top-level `dependencies` array, where each entry is:
            { "ref": "<bom-ref of package>", "dependsOn": ["<bom-ref>", ...] }
        `dependsOn` lists the CHILDREN of `ref`. We invert those edges to
        assign each child's parent, which lets us resolve chains of arbitrary
        depth (root -> direct dep -> transitive dep -> transitive-of-transitive...)
        instead of a single hardcoded level.
        """
        components = []
        by_id = {}

        for comp in data.get("components", []):
            # Prefer the CycloneDX bom-ref as the stable identifier since it is
            # unique per component even when the same package name appears at
            # multiple versions/positions in the SBOM. Fall back to name@version
            # if bom-ref is absent (some generators omit it).
            comp_id = comp.get("bom-ref") or f"{comp.get('name', 'unknown')}@{comp.get('version', '0.0.0')}"
            record = {
                "component_id": comp_id,
                "name": comp.get("name", "unknown"),
                "version": comp.get("version", "0.0.0"),
                "package_manager": comp.get("type", "library"),
                "license": self._extract_license(comp),
                "parent": None,  # resolved below from the dependency graph
            }
            components.append(record)
            by_id[comp_id] = record

        # Invert dependsOn edges into parent pointers.
        assigned = set()
        for edge in data.get("dependencies", []):
            parent_ref = edge.get("ref")
            if parent_ref not in by_id:
                continue
            for child_ref in edge.get("dependsOn", []):
                if child_ref in by_id and child_ref not in assigned:
                    # A component can technically be depended on by more than
                    # one package (a "diamond" dependency). Our schema stores a
                    # single parent per row (self-referential FK), so we keep
                    # the first relationship discovered and skip the rest.
                    # TODO: if full diamond/multi-parent support is needed,
                    # the schema would need a many-to-many edge table.
                    by_id[child_ref]["parent"] = parent_ref
                    assigned.add(child_ref)

        # If the SBOM has no `dependencies` graph at all (common in minimal
        # exports), every component is honestly treated as a root (depth 0)
        # rather than falsely grouped by namespace as before.
        return components

    def _parse_flat_list(self, data):
        components = []
        for comp in data:
            components.append({
                "component_id": comp.get("name", "unknown"),
                "name": comp.get("name", "unknown"),
                "version": comp.get("version", "0.0.0"),
                "package_manager": comp.get("package_manager", "npm"),
                "license": comp.get("license", "Unknown"),
                "parent": comp.get("parent"),
            })
        return components

    def _parse_generic_dependencies(self, data):
        components = []
        for comp in data.get("dependencies", []):
            components.append({
                "component_id": comp.get("name", "unknown"),
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
                name = row.get("name", row.get("package", "unknown"))
                components.append({
                    "component_id": name,
                    "name": name,
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
