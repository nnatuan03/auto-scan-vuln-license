from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .package_names import UNKNOWN_PACKAGE, resolve_package_name


PERMISSIVE = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "ISC",
    "MIT",
    "PSF-2.0",
    "Python-2.0",
    "Unlicense",
    "UPL-1.0",
    "WTFPL",
    "Zlib",
}
NOTICE = {
    "BlueOak-1.0.0",
    "CC-BY-4.0",
    "JSON",
}
RECIPROCAL = {
    "CDDL-1.0",
    "CDDL-1.1",
    "CPL-1.0",
    "EPL-1.0",
    "EPL-2.0",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "MPL-1.1",
    "MPL-2.0",
}
RESTRICTED = {
    "AGPL-3.0-only",
    "GPL-2.0-only",
    "GPL-2.0-with-classpath-exception",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "SSPL-1.0",
}


def _license_name(entry: dict[str, Any]) -> str:
    if "expression" in entry:
        return str(entry.get("expression") or "").strip()
    license_obj = entry.get("license")
    if not isinstance(license_obj, dict):
        return ""
    return str(
        license_obj.get("id")
        or license_obj.get("name")
        or license_obj.get("url")
        or ""
    ).strip()


def _component_name(component: dict[str, Any]) -> str:
    name = str(component.get("name") or "").strip()
    group = str(component.get("group") or "").strip()
    purl = str(component.get("purl") or "").strip()
    bom_ref = str(component.get("bom-ref") or "").strip()
    if group and name and not name.startswith(group):
        return f"{group}/{name}"
    if name:
        return name
    resolved = resolve_package_name(component, result_target=purl or bom_ref)
    if resolved.name != UNKNOWN_PACKAGE:
        return resolved.name
    return purl or bom_ref or UNKNOWN_PACKAGE


def _component_target(component: dict[str, Any]) -> str:
    return str(
        component.get("purl")
        or component.get("bom-ref")
        or component.get("name")
        or "-"
    )


def classify_license(name: str) -> tuple[str, str]:
    normalized = (name or "").strip()
    upper = normalized.upper()
    if not normalized or normalized == "LicenseRef-No-Declared-License":
        return "UNKNOWN", "unknown"
    if normalized.startswith("LicenseRef-"):
        return "UNKNOWN", "unknown"
    if normalized in RESTRICTED or any(token in upper for token in ("AGPL", "GPL", "SSPL")):
        return "HIGH", "restricted"
    if normalized in RECIPROCAL or any(token in upper for token in ("LGPL", "CDDL", "EPL", "MPL", "CPL", "OSL")):
        return "MEDIUM", "reciprocal"
    if normalized in PERMISSIVE:
        return "LOW", "permissive"
    if normalized in NOTICE:
        return "LOW", "notice"
    return "UNKNOWN", "unknown"


def licenses_from_sbom(sbom_path: Path) -> list[dict[str, str]]:
    with sbom_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    rows: list[dict[str, str]] = []
    for component in data.get("components") or []:
        if not isinstance(component, dict):
            continue
        package = _component_name(component)
        target = _component_target(component)
        licenses = component.get("licenses") or []

        names = [_license_name(entry) for entry in licenses if isinstance(entry, dict)]
        names = [name for name in names if name]
        if not names:
            names = ["LicenseRef-No-Declared-License"]

        for name in dict.fromkeys(names):
            severity, _ = classify_license(name)
            rows.append({
                "PkgName": package,
                "Name": name,
                "Severity": severity,
                "FilePath": target,
            })
    return rows


def _license_keys(data: dict[str, Any]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for result in data.get("Results") or []:
        for license_item in result.get("Licenses") or []:
            keys.add((
                str(license_item.get("PkgName") or license_item.get("Package") or ""),
                str(license_item.get("Name") or ""),
            ))
    return keys


def _ensure_results(data: dict[str, Any]) -> list[dict[str, Any]]:
    results = data.setdefault("Results", [])
    if not isinstance(results, list):
        data["Results"] = []
        results = data["Results"]
    return results


def augment_report_with_sbom_licenses(report_path: Path, sbom_path: Path) -> int:
    with report_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    inventory = licenses_from_sbom(sbom_path)
    existing = _license_keys(data)
    missing = [
        row for row in inventory
        if (row["PkgName"], row["Name"]) not in existing
    ]
    if not missing:
        return 0

    results = _ensure_results(data)
    results.append({
        "Target": str(sbom_path),
        "Class": "sbom-license-inventory",
        "Type": "cyclonedx",
        "Licenses": missing,
    })

    with report_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    return len(missing)
