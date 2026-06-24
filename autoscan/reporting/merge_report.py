"""
autoscan.reporting.merge_report
Usage:
    python -m autoscan.reporting.merge_report <services_dir> <output_html>

Merges all report.json found in immediate subfolders of <services_dir>,
generates a consolidated HTML + Excel report.
"""

import json
import sys
import os
from html import escape
from pathlib import Path
from collections import defaultdict
from datetime import datetime

from autoscan.license_inventory import classify_license
from autoscan.license_policy import is_manifest_package_name
from autoscan.package_names import canonical_pkg_key, resolve_package_name

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
NO_DECLARED_LICENSE = "LicenseRef-No-Declared-License"


def get_highest_severity(severities):
    if not severities:
        return "UNKNOWN"
    return min(severities, key=lambda s: SEVERITY_ORDER.get(s, 99))


def get_license_action(severity, category, license_name=""):
    category = (category or "").lower()
    severity = (severity or "").upper()
    license_name = license_name or ""
    if severity in ("CRITICAL", "HIGH") or "restricted" in category or "forbidden" in category:
        return ("Replace", "#e53e3e")
    elif severity in ("MEDIUM", "LOW") or "reciprocal" in category or "notice" in category:
        return ("Review", "#dd8500")
    # Unidentified licenses (LicenseRef-*) need manual review even if severity unknown
    if license_name.startswith("LicenseRef-") or severity == "UNKNOWN" or category in ("", "unknown"):
        return ("Review", "#dd8500")
    return ("OK", "#2d9e5f")


def get_license_badge_color(name):
    n = (name or "").upper()
    if any(x in n for x in ["GPL", "AGPL", "LGPL", "EUPL", "CDDL", "SSPL"]):
        return ("#e53e3e", "#fff0f0")
    elif any(x in n for x in ["MPL", "EPL", "OSL", "CPL"]):
        return ("#dd8500", "#fff8e6")
    elif any(x in n for x in ["MIT", "BSD", "ISC", "WTFPL", "UNLICENSE", "CC0", "ZLIB"]):
        return ("#2d9e5f", "#f0fff6")
    elif any(x in n for x in ["APACHE", "PSF", "PYTHON"]):
        return ("#2b6cb0", "#ebf4ff")
    elif any(x in n for x in ["COMMERCIAL", "PROPRIETARY"]):
        return ("#6b46c1", "#f5f0ff")
    return ("#4a5568", "#f7fafc")


def dependency_health_cell(health):
    if not isinstance(health, dict) or not health:
        return '<span class="health-chip health-ok">-</span>'
    status = str(health.get("status") or "-")
    issues = health.get("issues") or []
    cls = "health-ok" if status == "DEPENDENCY_HEALTH_OK" else "health-warn"
    detail = ""
    if issues:
        detail = "<div class=\"health-detail\">" + "<br>".join(
            "{0}: {1}".format(
                escape(str(issue.get("code") or "WARN")),
                escape(str(issue.get("message") or ""))[:180],
            )
            for issue in issues[:4]
        ) + "</div>"
    return '<span class="health-chip {0}">{1}</span>{2}'.format(cls, escape(status), detail)


def _without_license_paths(row):
    return {key: value for key, value in row.items() if key not in ("filepath", "filepaths")}

def _license_group_without_paths(group):
    clean = dict(group)
    clean["licenses"] = [_without_license_paths(row) for row in group.get("licenses", [])]
    clean["lics"] = [_without_license_paths(row) for row in group.get("lics", [])]
    return clean

def load_all_reports(be_dir):
    be_path = Path(be_dir)
    vuln_rows = []
    lic_rows  = []
    folders_found = []
    health_by_folder = {}

    for sub in sorted(be_path.iterdir()):
        if not sub.is_dir():
            continue
        report_json = sub / "report.json"
        if not report_json.exists():
            continue

        folder_name = sub.name
        folders_found.append(folder_name)

        try:
            data = json.loads(report_json.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"  [WARN] Cannot read {report_json}: {e}")
            continue
        metadata = data.get("Metadata") if isinstance(data.get("Metadata"), dict) else {}
        autoscan_metadata = metadata.get("AutoScan") if isinstance(metadata.get("AutoScan"), dict) else {}
        health_by_folder[folder_name] = autoscan_metadata.get("dependency_health") if isinstance(autoscan_metadata.get("dependency_health"), dict) else {}

        for result in data.get("Results", []):
            result_target = result.get("Target", "")
            result_class  = result.get("Class", "")
            for v in result.get("Vulnerabilities") or []:
                pkg_name = resolve_package_name(
                    v,
                    result_target=result_target,
                    result_class=result_class,
                ).name
                vuln_rows.append({
                    "folder":  folder_name,
                    "pkg":     pkg_name,
                    "version": v.get("InstalledVersion", ""),
                    "fixed":   v.get("FixedVersion", "-"),
                    "cve":     v.get("VulnerabilityID", ""),
                    "severity":v.get("Severity", "UNKNOWN"),
                    "title":   v.get("Title", ""),
                    "url":     "https://avd.aquasec.com/nvd/{0}".format(v.get("VulnerabilityID","").lower()),
                })
            # Result type can be "lang-pkgs" (with package), "license-file" (file-based), or "config-license"
            for lc in result.get("Licenses") or []:
                pkg_name = resolve_package_name(
                    lc,
                    result_target=result_target,
                    result_class=result_class,
                ).name
                if is_manifest_package_name(pkg_name):
                    continue

                lic_rows.append({
                    "folder":   folder_name,
                    "pkg":      pkg_name,
                    "license":  lc.get("Name", ""),
                    "severity": lc.get("Severity", "UNKNOWN"),
                    "filepath": lc.get("FilePath", "-") or "-",
                    "target":   result_target or "-",
                })

    return vuln_rows, lic_rows, folders_found, health_by_folder


def group_vulns(vuln_rows):
    groups = defaultdict(lambda: {
        "folders": [],
        "severities": [],
        "rows": [],
        "_seen_pkg": set(),
        "_display_name": "",
    })
    for r in vuln_rows:
        # Use a canonical key (group/name lower-cased) so the same package
        # spelled "ch.qos.logback/logback-classic" or "ch.qos.logback:logback-classic"
        # ends up in the same group instead of being reported twice.
        key = canonical_pkg_key(r.get("pkg", "")) or r.get("pkg", "")
        g = groups[key]
        if not g["_display_name"]:
            g["_display_name"] = r.get("pkg", "")
        if r["folder"] not in g["folders"]:
            g["folders"].append(r["folder"])
        # Keep only exact duplicate rows at this stage. The final report
        # aggregates by CVE below so each package shows every CVE only once,
        # while still preserving all unique installed/fixed versions.
        version = (r.get("version") or "").strip() or "-"
        fixed = (r.get("fixed") or "").strip() or "-"
        dedup_key = (
            r.get("folder", ""),
            r.get("cve", ""),
            version,
            fixed,
            r.get("severity", "UNKNOWN"),
            r.get("title", ""),
        )
        if dedup_key in g["_seen_pkg"]:
            continue
        g["_seen_pkg"].add(dedup_key)
        g["severities"].append(r["severity"])
        g["rows"].append(r)

    merged = _merge_no_group_entries(groups)
    result = []
    for pkg_key, g in merged.items():
        vulns = _aggregate_vulns_by_cve(g["rows"])
        severities = [v["severity"] for v in vulns] or ["UNKNOWN"]
        highest = get_highest_severity(severities)
        result.append({
            "pkg": g["_display_name"] or pkg_key,
            "severity": highest,
            "versions": sorted({
                version
                for v in vulns
                for version in v.get("versions", [])
                if version and version != "-"
            }),
            "fixed_versions": sorted({
                fixed
                for v in vulns
                for fixed in v.get("fixed_versions", [])
                if fixed and fixed != "-"
            }),
            "folders": sorted(g["folders"]),
            "vulns": sorted(
                vulns,
                key=lambda r: (
                    SEVERITY_ORDER.get(r["severity"], 99),
                    str(r.get("cve") or "").lower(),
                ),
            ),
        })
    result.sort(key=lambda x: (
        0 if len(x["vulns"]) > 1 else 1,
        SEVERITY_ORDER.get(x["severity"], 99),
        x["pkg"].lower(),
    ))
    return result


def _append_unique(values: list[str], value: object, *, keep_dash: bool = False) -> None:
    text = str(value or "").strip()
    if not text:
        return
    if text == "-" and not keep_dash:
        return
    if text not in values:
        values.append(text)


def _aggregate_vulns_by_cve(rows: list[dict]) -> list[dict]:
    """Collapse repeated package findings so each CVE appears once."""
    by_cve: dict[str, dict] = {}
    for row in rows:
        cve = str(row.get("cve") or "").strip()
        if not cve:
            cve = str(row.get("title") or "").strip() or "UNKNOWN"
        item = by_cve.setdefault(cve, {
            "cve": cve,
            "severity": "UNKNOWN",
            "versions": [],
            "fixed_versions": [],
            "folders": [],
            "affected_instances": [],
            "_seen_instances": set(),
            "titles": [],
            "title": "",
            "url": row.get("url", ""),
        })
        item["severity"] = get_highest_severity([
            item.get("severity") or "UNKNOWN",
            row.get("severity") or "UNKNOWN",
        ])
        if not item.get("url") and row.get("url"):
            item["url"] = row.get("url")
        _append_unique(item["versions"], row.get("version"), keep_dash=True)
        _append_unique(item["fixed_versions"], row.get("fixed"))
        _append_unique(item["folders"], row.get("folder"))
        instance = {
            "service": str(row.get("folder") or "-").strip() or "-",
            "version": str(row.get("version") or "-").strip() or "-",
            "fixed": str(row.get("fixed") or "-").strip() or "-",
        }
        instance_key = (instance["service"], instance["version"], instance["fixed"])
        if instance_key not in item["_seen_instances"]:
            item["_seen_instances"].add(instance_key)
            item["affected_instances"].append(instance)
        title = str(row.get("title") or "").strip()
        if title:
            _append_unique(item["titles"], title)
            if not item["title"]:
                item["title"] = title

    for item in by_cve.values():
        if not item["versions"]:
            item["versions"].append("-")
        item["versions"].sort()
        item["fixed_versions"].sort()
        item["folders"].sort()
        item["affected_instances"].sort(key=lambda row: (row["service"].lower(), row["version"], row["fixed"]))
        item.pop("_seen_instances", None)
        item["version"] = "\n".join(item["versions"])
        item["fixed"] = "\n".join(item["fixed_versions"]) if item["fixed_versions"] else "-"

    return list(by_cve.values())


def group_licenses(lic_rows):
    groups = defaultdict(lambda: {
        "folders": [],
        "severities": [],
        "rows": [],
        "_licenses": {},
        "_display_name": "",
    })
    for r in lic_rows:
        license_name = str(r.get("license", "") or "").strip()
        severity, category = classify_license(license_name)
        source_severity = str(r.get("severity") or "UNKNOWN").strip().upper() or "UNKNOWN"
        if severity == "UNKNOWN" and source_severity in SEVERITY_ORDER:
            severity = source_severity
        # Use a canonical key (group/name lower-cased) so the same package
        # spelled "ch.qos.logback/logback-classic" or "ch.qos.logback:logback-classic"
        # ends up in the same group instead of being reported twice.
        key = canonical_pkg_key(r.get("pkg", "")) or r.get("pkg", "")
        g = groups[key]
        if not g["_display_name"]:
            g["_display_name"] = r.get("pkg", "")
        if r["folder"] not in g["folders"]:
            g["folders"].append(r["folder"])
        combo = (license_name, severity, category)
        license_row = g["_licenses"].setdefault(combo, {
            "folder": r.get("folder", ""),
            "pkg": r.get("pkg", ""),
            "license": license_name,
            "severity": severity,
            "category": category,
            "filepath": r.get("filepath", "-") or "-",
            "target": r.get("target", "-") or "-",
            "folders": [],
            "filepaths": [],
            "targets": [],
        })
        _append_unique(license_row["folders"], r.get("folder"))
        _append_unique(license_row["filepaths"], r.get("filepath"))
        _append_unique(license_row["targets"], r.get("target"))

    for g in groups.values():
        rows = list(g["_licenses"].values())
        has_declared_license = any(row.get("license") != NO_DECLARED_LICENSE for row in rows)
        if has_declared_license:
            rows = [row for row in rows if row.get("license") != NO_DECLARED_LICENSE]
        for row in rows:
            if not row["folders"]:
                row["folders"].append(row.get("folder") or "-")
            if not row["filepaths"]:
                row["filepaths"].append(row.get("filepath") or "-")
            if not row["targets"]:
                row["targets"].append(row.get("target") or "-")
            row["folder"] = "\n".join(row["folders"])
            row["filepath"] = "\n".join(row["filepaths"])
            row["target"] = "\n".join(row["targets"])
        g["rows"] = rows
        g["severities"] = [row.get("severity") or "UNKNOWN" for row in rows]

    return _finalise_license_groups(groups)


def _leaf_pkg_name(name: str) -> str:
    """Return just the artifact name (after the last ``/`` or ``:``)."""
    text = str(name or "").strip().lower()
    if not text:
        return ""
    for sep in ("/", ":"):
        if sep in text:
            return text.rsplit(sep, 1)[1]
    return text


def _merge_no_group_entries(groups: dict) -> dict:
    """Fold groups whose artifact leaf name appears with and without a group.

    A CycloneDX SBOM or Trivy report may emit the same Maven artifact in
    two equivalent shapes — once with ``group + name`` fields
    (``ch.qos.logback/logback-classic``) and once with a flattened coordinate
    in the name field (``ch.qos.logback:logback-classic``). After
    ``canonical_pkg_key`` those collapse, but a third shape (artifact name
    only, e.g. ``jakarta.annotation-api``) cannot be disambiguated from a
    real differently-grouped artifact by string rules alone.

    This helper merges groups that share a leaf name *only* when the no-group
    form is unique for that leaf. If two distinct groups (e.g.
    ``com.lib-a/spring-core`` and ``com.lib-b/spring-core``) genuinely share
    an artifact name, we keep them separate to avoid silently mixing
    different artifacts.

    The function preserves the per-group dedup semantics of the caller: rows
    in each group dict are expected to already be deduplicated. The merge
    re-applies dedup based on the row content the caller cares about —
    for vulnerabilities that's ``(CVE, version)``; for licenses that's
    ``(license, severity, category)``. We use a conservative key of the full
    row's tuple of values to be safe across both call sites.
    """
    # Bucket groups by leaf name.
    leaf_buckets: dict[str, list[str]] = defaultdict(list)
    for key in groups:
        leaf = _leaf_pkg_name(key)
        if leaf:
            leaf_buckets[leaf].append(key)

    # Decide which groups to merge. A leaf with exactly one key, or where one
    # key is the no-group leaf and the other is a fully-qualified form, gets
    # merged into a single representative key. Skip the leaf bucket if more
    # than one fully-qualified key remains — that means two different groups
    # genuinely share an artifact name and we must keep them apart.
    merge_target: dict[str, str] = {}
    for leaf, keys in leaf_buckets.items():
        if len(keys) < 2:
            continue
        no_group_key = leaf
        fully_qualified = [k for k in keys if k != no_group_key and ("/" in k or ":" in k)]
        if len(fully_qualified) >= 2:
            # Multiple distinct groups share this artifact leaf — keep
            # them separate to avoid silently mixing different artifacts.
            continue
        if fully_qualified:
            # Merge the no-group entry into the fully-qualified one.
            merge_target[no_group_key] = fully_qualified[0]
        else:
            # All entries are no-group spellings — they're the same thing.
            primary = keys[0]
            for k in keys[1:]:
                merge_target[k] = primary

    # Apply merges.
    merged: dict[str, dict] = {}
    for key, g in groups.items():
        target_key = merge_target.get(key, key)
        if target_key not in merged:
            merged[target_key] = {
                "folders": [],
                "severities": [],
                "rows": [],
                "_seen": set(),
                "_display_name": "",
            }
        target = merged[target_key]
        if not target["_display_name"]:
            # Prefer a fully-qualified display name when available.
            target["_display_name"] = g["_display_name"]
        for folder in g["folders"]:
            if folder not in target["folders"]:
                target["folders"].append(folder)
        for sev in g["severities"]:
            target["severities"].append(sev)
        # Carry the per-group dedup set if the caller populated one under a
        # different name (``_seen_pkg`` for vulnerabilities).
        for seen_name in ("_seen", "_seen_pkg"):
            for k in g.get(seen_name, ()):
                target["_seen"].add(k)
        for row in g["rows"]:
            merged[target_key]["rows"].append(row)

    # Re-dedupe rows in each merged group using the full row tuple. This
    # is safe across call sites: for vulnerabilities the CVE+version combo
    # is what matters; for licenses it's the (license, severity, category)
    # combo. Using the full row tuple keeps the strongest possible dedup
    # without losing the per-site semantics.
    for target in merged.values():
        seen_rows: dict[tuple, dict] = {}
        unique_rows: list = []
        for row in target["rows"]:
            # Frozen tuple of the values that are dedup-relevant for both
            # call sites. We drop None / empty fields for robustness.
            signature = (
                row.get("cve") or row.get("license") or "",
                row.get("folder") if row.get("cve") else "",
                row.get("version") or "",
                row.get("fixed") or "",
                row.get("severity") or "",
                row.get("title") or "",
            )
            if signature in seen_rows:
                existing = seen_rows[signature]
                _merge_row_traceability(existing, row)
                continue
            _merge_row_traceability(row, row)
            seen_rows[signature] = row
            unique_rows.append(row)
        target["rows"] = unique_rows

    return merged


def _merge_row_traceability(target: dict, row: dict) -> None:
    """Merge service, target, and filepath breadcrumbs for deduped rows."""
    for scalar_field, list_field in (
        ("folder", "folders"),
        ("target", "targets"),
        ("filepath", "filepaths"),
    ):
        values = target.setdefault(list_field, [])
        if not isinstance(values, list):
            values = [values]
            target[list_field] = values
        source_values = row.get(list_field)
        if isinstance(source_values, list):
            for value in source_values:
                _append_unique(values, value)
        else:
            _append_unique(values, source_values)
        _append_unique(values, row.get(scalar_field))
        if values:
            target[scalar_field] = "\n".join(values)


def _finalise_license_groups(groups: dict) -> list[dict]:
    """Build the final list of license groups after the no-group merge."""
    merged = _merge_no_group_entries(groups)
    result = []
    for pkg_key, g in merged.items():
        highest = get_highest_severity(g["severities"])
        license_names = sorted({r["license"] for r in g["rows"] if r.get("license")})
        categories = sorted({r["category"] for r in g["rows"] if r.get("category")})
        action, action_color = get_license_action(highest, ",".join(categories), ",".join(license_names))
        result.append({
            "pkg": g["_display_name"] or pkg_key,
            "license_names": license_names,
            "severity": highest,
            "categories": categories,
            "action": action,
            "action_color": action_color,
            "folders": sorted(g["folders"]),
            "licenses": sorted(
                g["rows"],
                key=lambda r: (
                    SEVERITY_ORDER.get(r["severity"], 99),
                    str(r.get("license") or "").lower(),
                    str(r.get("folder") or "").lower(),
                ),
            ),
        })
    result.sort(key=lambda x: (
        0 if len(x["licenses"]) > 1 else 1,
        SEVERITY_ORDER.get(x["severity"], 99),
        x["pkg"].lower(),
    ))
    return result


SEV_COLOR = {
    "CRITICAL": "#e53e3e",
    "HIGH":     "#dd6b20",
    "MEDIUM":   "#dd8500",
    "LOW":      "#2d9e5f",
    "UNKNOWN":  "#718096",
}
ORDER = SEVERITY_ORDER


def sev_chip(sev):
    c = SEV_COLOR.get(sev, "#718096")
    return '<span class="sev-chip" style="color:{0};border-color:{0}40;background:{0}12">{1}</span>'.format(c, escape(str(sev)))


def lic_chip(name):
    border, bg = get_license_badge_color(name)
    return '<span class="lic-chip" style="color:{0};background:{1};border-color:{0}30">{2}</span>'.format(border, bg, escape(str(name)))


def action_chip(action, color):
    return '<span class="action-chip" style="color:{0};border-color:{0}50;background:{0}10">{1}</span>'.format(color, escape(str(action)))


def line_stack(items):
    values = [str(item) for item in items if str(item or "").strip()]
    if not values:
        values = ["-"]
    return '<div class="line-stack">' + "".join("<div>{0}</div>".format(escape(value)) for value in values) + "</div>"


def html_line_stack(items):
    values = [str(item) for item in items if str(item or "").strip()]
    if not values:
        values = ["-"]
    return '<div class="line-stack">' + "".join("<div>{0}</div>".format(value) for value in values) + "</div>"


def unique_values(items):
    values = []
    seen = set()
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        values.append(value)
    return values


def paths_html(folders, max_show=4):
    if not folders:
        return '<span style="color:#9ca3af;font-size:11px">-</span>'
    visible = folders[:max_show]
    hidden  = folders[max_show:]
    uid = abs(hash(str(folders))) % 999999
    html = '<div class="paths-wrap">'
    for f in visible:
        html += '<div class="path-item">{0}</div>'.format(escape(str(f)))
    if hidden:
        html += '<div class="path-more" onclick="togglePaths({0},this)">+ {1} more</div>'.format(uid, len(hidden))
        html += '<div class="path-hidden" id="ph-{0}" style="display:none">'.format(uid)
        for f in hidden:
            html += '<div class="path-item">{0}</div>'.format(escape(str(f)))
        html += '</div>'
    html += '</div>'
    return html

def affected_instances_html(instances, max_show=6):
    if not instances:
        return '<span style="color:#9ca3af;font-size:11px">-</span>'
    lines = []
    for item in instances:
        service = str(item.get("service") or "-")
        version = str(item.get("version") or "-")
        fixed = str(item.get("fixed") or "-")
        if fixed and fixed != "-":
            lines.append(f"{service}: {version} → {fixed}")
        else:
            lines.append(f"{service}: {version}")
    return paths_html(lines, max_show=max_show)


def generate_html(be_dir, output_html):
    vuln_rows, lic_rows, folders_found, health_by_folder = load_all_reports(be_dir)
    vuln_groups = group_vulns(vuln_rows)
    lic_groups  = group_licenses(lic_rows)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    vuln_sev = defaultdict(int)
    for g in vuln_groups:
        for vuln in g.get("vulns", []):
            vuln_sev[vuln.get("severity") or "UNKNOWN"] += 1

    lic_sev = defaultdict(int)
    for g in lic_groups:
        for license_item in g.get("licenses", []):
            lic_sev[license_item.get("severity") or "UNKNOWN"] += 1
    total_unique_vulns = sum(len(g.get("vulns", [])) for g in vuln_groups)
    total_unique_licenses = sum(len(g.get("licenses", [])) for g in lic_groups)

    def vuln_table_rows():
        rows = ""
        sorted_vulns = sorted(vuln_groups, key=lambda x: (
            0 if len(x["vulns"]) > 1 else 1,
            ORDER.get(x["severity"], 99),
            x["pkg"].lower(),
        ))
        for group_index, r in enumerate(sorted_vulns):
            group_bg = "grp-even" if (group_index % 2 == 0) else "grp-odd"
            vulns = r["vulns"]
            if not vulns:
                vulns = [{
                    "cve": "-",
                    "severity": r.get("severity") or "UNKNOWN",
                    "url": "",
                    "versions": r.get("versions") or ["-"],
                    "fixed_versions": r.get("fixed_versions") or [],
                    "titles": [],
                }]
            rowspan = len(vulns)
            version_lines = unique_values(
                version
                for vuln in vulns
                for version in (vuln.get("versions") or ["-"])
            ) or ["-"]
            fixed_lines = unique_values(
                fixed
                for vuln in vulns
                for fixed in (vuln.get("fixed_versions") or ["-"])
            ) or ["-"]
            severity_attr = ",".join(unique_values(v.get("severity", "") for v in vulns))
            cve_sort = " ".join(v.get("cve", "") for v in vulns)
            search_text = " ".join([
                r["pkg"],
                cve_sort,
                severity_attr,
                " ".join(version_lines),
                " ".join(fixed_lines),
                " ".join(r["folders"]),
                " ".join(
                    "{0} {1} {2}".format(
                        item.get("service", ""),
                        item.get("version", ""),
                        item.get("fixed", ""),
                    )
                    for v in vulns
                    for item in v.get("affected_instances", [])
                ),
                " ".join(title for v in vulns for title in v.get("titles", [])),
            ])
            rows += '<tbody class="vuln-group {0}" data-severity="{1}" data-severities="{2}" data-pkg="{3}" data-search="{4}" data-sort-package="{5}" data-sort-cve="{6}" data-sort-severity="{7}" data-sort-installed="{8}" data-sort-fix="{9}" data-sort-services="{10}">'.format(
                group_bg,
                escape(r["severity"]),
                escape(severity_attr),
                escape(r["pkg"]),
                escape(search_text.lower()),
                escape(r["pkg"].lower()),
                escape(cve_sort.lower()),
                ORDER.get(r["severity"], 99),
                escape(" ".join(version_lines).lower()),
                escape(" ".join(fixed_lines).lower()),
                escape(" ".join(r["folders"]).lower()),
            )
            for vuln_index, v in enumerate(vulns):
                severity = v.get("severity") or "UNKNOWN"
                row_class = "grp-end" if vuln_index == rowspan - 1 else "grp-mid"
                cve_label = escape(v.get("cve") or "-")
                cve_url = escape(v.get("url") or "")
                cve_html = '<a href="{0}" target="_blank" class="cve-link">{1}</a>'.format(cve_url, cve_label) if cve_url else cve_label
                rows += '<tr class="data-row lic-grp vuln-row {0} {1}" data-severity="{2}" data-severities="{3}" data-pkg="{4}">'.format(
                    group_bg,
                    row_class,
                    escape(severity),
                    escape(severity_attr),
                    escape(r["pkg"]),
                )
                if vuln_index == 0:
                    rows += '<td class="pkg-name vuln-merged-cell" rowspan="{0}">{1}</td>'.format(rowspan, escape(r["pkg"]))
                rows += '<td>{0}</td>'.format(cve_html)
                rows += '<td class="severity-cell severity-{0}" data-value="{1}">{2}</td>'.format(
                    escape(severity.lower()),
                    ORDER.get(severity, 99),
                    escape(severity),
                )
                rows += '<td>{0}</td>'.format(line_stack(v.get("versions") or ["-"]))
                rows += '<td>{0}</td>'.format(line_stack(v.get("fixed_versions") or ["-"]))
                if vuln_index == 0:
                    instances = [item for vuln in vulns for item in vuln.get("affected_instances", [])]
                    rows += '<td class="vuln-merged-cell" rowspan="{0}">{1}</td>'.format(rowspan, affected_instances_html(instances))
                rows += '</tr>'
            rows += '</tbody>'
        return rows or '<tbody class="vuln-empty"><tr><td colspan="6" class="no-data">No vulnerabilities found.</td></tr></tbody>'

    def lic_table_rows():
        rows = ""
        sorted_lics = sorted(lic_groups, key=lambda x: (
            0 if len(x["licenses"]) > 1 else 1,
            ORDER.get(x["severity"], 99),
            x["pkg"].lower(),
        ))
        for group_index, r in enumerate(sorted_lics):
            group_bg = "grp-even" if (group_index % 2 == 0) else "grp-odd"
            licenses = r["licenses"]
            if not licenses:
                licenses = [{
                    "license": "-",
                    "severity": r.get("severity") or "UNKNOWN",
                    "folders": r.get("folders") or ["-"],
                    "filepaths": [],
                }]
            rowspan = len(licenses)
            severity_attr = ",".join(unique_values(lic.get("severity", "") for lic in licenses))
            license_sort = " ".join(lic.get("license", "") for lic in licenses)
            search_text = " ".join([
                r["pkg"],
                license_sort,
                severity_attr,
                " ".join(r["folders"]),
            ])
            rows += '<tbody class="lic-group {0}" data-severity="{1}" data-severities="{2}" data-pkg="{3}" data-search="{4}" data-sort-package="{5}" data-sort-license="{6}" data-sort-severity="{7}" data-sort-services="{8}">'.format(
                group_bg,
                escape(r["severity"]),
                escape(severity_attr),
                escape(r["pkg"]),
                escape(search_text.lower()),
                escape(r["pkg"].lower()),
                escape(license_sort.lower()),
                ORDER.get(r["severity"], 99),
                escape(" ".join(r["folders"]).lower()),
            )
            for lic_index, lic in enumerate(licenses):
                severity = lic.get("severity") or "UNKNOWN"
                row_class = "grp-end" if lic_index == rowspan - 1 else "grp-mid"
                rows += '<tr class="data-row lic-grp license-row {0} {1}" data-severity="{2}" data-severities="{3}" data-pkg="{4}">'.format(
                    group_bg,
                    row_class,
                    escape(severity),
                    escape(severity_attr),
                    escape(r["pkg"]),
                )
                if lic_index == 0:
                    rows += '<td class="pkg-name vuln-merged-cell" rowspan="{0}">{1}</td>'.format(rowspan, escape(r["pkg"]))
                rows += '<td>{0}</td>'.format(lic_chip(lic.get("license", "") or "-"))
                rows += '<td class="severity-cell severity-{0}" data-value="{1}">{2}</td>'.format(
                    escape(severity.lower()),
                    ORDER.get(severity, 99),
                    escape(severity),
                )
                if lic_index == 0:
                    rows += '<td class="vuln-merged-cell" rowspan="{0}">{1}</td>'.format(rowspan, paths_html(r["folders"]))
                rows += '</tr>'
            rows += '</tbody>'
        return rows or '<tbody class="lic-empty"><tr><td colspan="4" class="no-data">No license issues found.</td></tr></tbody>'

    def metric_card(label, value, sub, color):
        return '<div class="metric-card"><div class="metric-value" style="color:{0}">{1}</div><div class="metric-label">{2}</div><div class="metric-sub">{3}</div></div>'.format(color, value, label, sub)

    metrics = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        metrics += metric_card(sev, vuln_sev.get(sev, 0), "CVEs", SEV_COLOR[sev])
    metrics += metric_card("SERVICES", len(folders_found), "scanned", "#3182ce")
    def stat_block(sev, count, tab, filter_id, filter_fn):
        c = SEV_COLOR.get(sev, "#718096")
        return '<div class="sev-stat" onclick="switchTab(\'{0}\');document.getElementById(\'{1}\').value=\'{2}\';{3}()"><div class="sev-stat-bar" style="background:{4}"></div><div class="sev-stat-number" style="color:{4}">{5:02d}</div><div class="sev-stat-label" style="color:{4}">{2}</div></div>'.format(
            tab, filter_id, sev, filter_fn, c, count)

    lic_stats  = "".join(stat_block(s, lic_sev.get(s,0),  "lic",  "licSevFilter",  "filterLic")  for s in ["CRITICAL","HIGH","MEDIUM","LOW"])
    vuln_stats = "".join(stat_block(s, vuln_sev.get(s,0), "vuln", "vulnSevFilter", "filterVuln") for s in ["CRITICAL","HIGH","MEDIUM","LOW"])

    all_cats = sorted({cat for g in lic_groups for cat in g.get("categories", []) if cat})
    cat_options = "\n".join('<option value="{0}">{0}</option>'.format(c) for c in all_cats)

    services_rows = "".join(
        '<tr class="data-row"><td style="color:var(--text-muted);font-family:IBM Plex Mono,monospace;font-size:11px">{0:02d}</td><td class="pkg-name">{1}</td><td>{2}</td><td><span class="fix-version">found</span></td></tr>'.format(
            i + 1,
            f,
            dependency_health_cell(health_by_folder.get(f)),
        )
        for i, f in enumerate(folders_found)
    )

    # Escape </script> to prevent JSON data from breaking the script block
    vuln_json_data = json.dumps(vuln_groups, ensure_ascii=False).replace('</script>', '<\\/script>').replace('<!--', '<\\!--')
    lic_json_data  = json.dumps([_license_group_without_paths(group) for group in lic_groups], ensure_ascii=False).replace('</script>', '<\\/script>').replace('<!--', '<\\!--')

    be_name = Path(be_dir).name

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Consolidated Security Report</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/xlsx-js-style@1.2.0/dist/xlsx.bundle.js"></script>
<style>
  :root {
    --navy-950:#0a0f1e;--navy-900:#0d1629;--navy-800:#112240;--navy-700:#1a3356;
    --slate-400:#8fa3be;--slate-300:#b8cce0;--slate-200:#d4e2f0;--slate-100:#eaf1f8;--slate-50:#f5f8fc;
    --white:#fff;--text-primary:#1a2332;--text-secondary:#4a5e72;--text-muted:#8fa3be;
    --border:#dde8f2;--border-strong:#c4d4e5;--accent:#2563eb;--radius:4px;--radius-lg:8px;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'IBM Plex Sans',-apple-system,sans-serif;background:var(--slate-50);color:var(--text-primary);font-size:13px;line-height:1.5}
  .report-header{background:linear-gradient(135deg,var(--navy-950) 0%,var(--navy-800) 60%,var(--navy-700) 100%);position:relative;overflow:hidden}
  .report-header::before{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:repeating-linear-gradient(90deg,transparent,transparent 80px,rgba(255,255,255,.015) 80px,rgba(255,255,255,.015) 81px),repeating-linear-gradient(0deg,transparent,transparent 80px,rgba(255,255,255,.015) 80px,rgba(255,255,255,.015) 81px);pointer-events:none}
  .header-top{display:flex;align-items:center;justify-content:space-between;padding:24px 40px 20px;border-bottom:1px solid rgba(255,255,255,.08)}
  .report-brand{display:flex;align-items:center;gap:14px}
  .brand-mark{width:36px;height:36px;background:linear-gradient(135deg,#2563eb,#1d4ed8);border-radius:var(--radius);display:flex;align-items:center;justify-content:center;font-family:'IBM Plex Mono',monospace;font-size:13px;font-weight:600;color:#fff;flex-shrink:0}
  .report-title{font-size:15px;font-weight:600;color:#fff;letter-spacing:.01em}
  .report-subtitle{font-size:11px;color:var(--slate-400);margin-top:1px;letter-spacing:.04em;text-transform:uppercase}
  .header-meta{text-align:right}
  .meta-item{font-size:11px;color:var(--slate-400);font-family:'IBM Plex Mono',monospace}
  .meta-item span{color:var(--slate-300);font-weight:500}
  .metrics-bar{display:flex;padding:20px 40px 24px;overflow-x:auto}
  .metric-card{flex:1;min-width:90px;padding:12px 20px;border-right:1px solid rgba(255,255,255,.07)}
  .metric-card:last-child{border-right:none}
  .metric-value{font-size:28px;font-weight:700;font-family:'IBM Plex Mono',monospace;line-height:1;margin-bottom:4px}
  .metric-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:rgba(255,255,255,.5);margin-bottom:1px}
  .metric-sub{font-size:10px;color:rgba(255,255,255,.3)}
  .nav-tabs{display:flex;padding:0 40px;gap:2px;border-top:1px solid rgba(255,255,255,.06)}
  .nav-tab{padding:12px 20px;font-size:12px;font-weight:500;color:var(--slate-400);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;user-select:none;white-space:nowrap}
  .nav-tab:hover{color:var(--slate-200)}
  .nav-tab.active{color:#fff;border-bottom-color:#3b82f6;font-weight:600}
  .content{max-width:1600px;margin:0 auto;padding:28px 40px 48px}
  .tab-panel{display:none}.tab-panel.active{display:block}
  .section-header{display:flex;align-items:baseline;gap:10px;margin-bottom:16px}
  .section-title{font-size:14px;font-weight:600;color:var(--text-primary)}
  .section-desc{font-size:12px;color:var(--text-muted)}
  .toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
  .search-input{padding:7px 12px;border:1px solid var(--border-strong);border-radius:var(--radius);font-size:12px;font-family:'IBM Plex Sans',sans-serif;outline:none;background:#fff;color:var(--text-primary);min-width:200px;transition:border-color .15s}
  .search-input:focus{border-color:var(--accent)}
  .filter-select{padding:7px 10px;border:1px solid var(--border-strong);border-radius:var(--radius);font-size:12px;font-family:'IBM Plex Sans',sans-serif;outline:none;background:#fff;color:var(--text-secondary)}
  .btn{padding:7px 14px;border:none;border-radius:var(--radius);font-size:12px;font-family:'IBM Plex Sans',sans-serif;font-weight:500;cursor:pointer;transition:opacity .15s;white-space:nowrap}
  .btn:hover{opacity:.85}
  .btn-success{background:#1a7a4a;color:#fff}
  .btn-ghost{background:var(--slate-100);color:var(--text-secondary);border:1px solid var(--border)}
  .toolbar-right{margin-left:auto;display:flex;gap:8px;align-items:center}
  .row-count{font-size:12px;color:var(--text-muted);font-family:'IBM Plex Mono',monospace}
  .table-wrap{background:#fff;border:1px solid var(--border);border-radius:var(--radius-lg);overflow:hidden}
  .table-scroll{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  thead{background:var(--navy-900)}
  thead th{padding:10px 14px;text-align:left;font-size:10.5px;font-weight:600;color:var(--slate-400);letter-spacing:.08em;text-transform:uppercase;cursor:pointer;user-select:none;white-space:nowrap;border-right:1px solid rgba(255,255,255,.05);transition:color .15s}
  thead th:last-child{border-right:none}
  thead th:hover{color:var(--slate-200)}
  .si{margin-left:4px;opacity:.4;font-size:10px}
  tbody tr{border-bottom:1px solid var(--border)}
  tbody tr:last-child{border-bottom:none}
  .data-row:hover td{background:var(--slate-50)}
  td{padding:10px 14px;color:var(--text-primary);vertical-align:top}
  tr.hidden{display:none!important}
  /* ── Merged license groups ── */
  /* Inner rows of a group: no bottom border (looks merged) */
  .lic-grp.grp-mid td{border-bottom:none}
  /* Last row of a group: solid divider between groups */
  .lic-grp.grp-end td{border-bottom:1px solid var(--border-strong)}
  /* Alternating background per group */
  .lic-grp.grp-even td{background:#ffffff}
  .lic-grp.grp-odd  td{background:#f4f8fc}
  /* Hover highlights the whole hovered row regardless of group color */
  .lic-grp:hover td{background:#eaf2fb}
  tbody.vuln-group.hidden,tbody.lic-group.hidden{display:none}
  .vuln-merged-cell{vertical-align:middle}
  .vuln-row.grp-mid td:not(.vuln-merged-cell){border-bottom:1px solid var(--border)}
  .severity-cell{font-weight:700;color:#fff;text-align:left;vertical-align:middle;letter-spacing:.03em}
  .severity-critical{background:#8b0000!important}
  .severity-high{background:#ff0000!important}
  .severity-medium{background:#ffc000!important}
  .severity-low{background:#92d050!important;color:#fff}
  .severity-unknown{background:#718096!important;color:#fff}
  .no-data{text-align:center;padding:48px;color:var(--text-muted);font-size:13px}
  .pkg-name{font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:600;color:var(--navy-800)}
  .cve-link{font-family:'IBM Plex Mono',monospace;font-size:12px;color:#2563eb;text-decoration:none;font-weight:500}
  .cve-link:hover{text-decoration:underline}
  .version-tag{font-family:'IBM Plex Mono',monospace;font-size:11px;background:var(--slate-100);color:var(--text-secondary);padding:2px 7px;border-radius:var(--radius);border:1px solid var(--border);display:inline-block}
  .fix-version{font-family:'IBM Plex Mono',monospace;font-size:11px;background:#f0fff6;color:#1a7a4a;padding:2px 7px;border-radius:var(--radius);border:1px solid #c6f6d5;display:inline-block}
  .health-chip{display:inline-flex;align-items:center;padding:3px 7px;border-radius:var(--radius);font-size:10px;font-weight:700;font-family:'IBM Plex Mono',monospace;border:1px solid var(--border)}
  .health-ok{color:#1a7a4a;background:#f0fff6;border-color:#b8e6c8}
  .health-warn{color:#9a5b00;background:#fff8e6;border-color:#f3c77b}
  .health-detail{margin-top:5px;color:var(--text-muted);font-size:11px;line-height:1.4;max-width:520px}
  .sev-chip{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.05em;padding:2px 8px;border-radius:var(--radius);border:1px solid}
  .lic-chip{display:inline-block;font-size:11px;font-weight:500;padding:2px 8px;border-radius:var(--radius);border:1px solid;margin:2px 2px 2px 0;white-space:nowrap}
  .action-chip{display:inline-block;font-size:11px;font-weight:600;letter-spacing:.04em;padding:2px 10px;border-radius:var(--radius);border:1px solid;text-transform:uppercase}
  .paths-wrap{display:flex;flex-direction:column;gap:2px;min-width:200px}
  .path-item{font-family:'IBM Plex Mono',monospace;font-size:10.5px;color:#4a5568;background:#f5f8fc;border:1px solid #dde8f2;border-radius:3px;padding:1px 6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:300px}
  .path-more{font-size:11px;color:#2563eb;cursor:pointer;padding:1px 4px;user-select:none}
  .path-more:hover{text-decoration:underline}
  .line-stack{display:flex;flex-direction:column;gap:4px;align-items:flex-start}
  .line-stack>div{min-height:20px;line-height:1.45}
  .summary-grid{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:4px}
  .summary-block{background:#fff;border:1px solid var(--border);border-radius:var(--radius-lg);overflow:hidden}
  .summary-block-header{background:var(--navy-900);padding:14px 20px;border-bottom:1px solid var(--navy-700)}
  .summary-block-title{font-size:12px;font-weight:700;color:var(--slate-300);letter-spacing:.06em;text-transform:uppercase}
  .summary-block-desc{font-size:11px;color:var(--slate-400);margin-top:3px}
  .summary-block-body{display:grid;grid-template-columns:repeat(4,1fr)}
  .sev-stat{padding:28px 16px 24px;text-align:center;border-right:1px solid var(--border);position:relative;cursor:pointer;transition:background .15s}
  .sev-stat:last-child{border-right:none}
  .sev-stat:hover{background:var(--slate-50)}
  .sev-stat-bar{position:absolute;top:0;left:0;right:0;height:3px}
  .sev-stat-number{font-family:'IBM Plex Mono',monospace;font-size:40px;font-weight:700;line-height:1;margin-bottom:8px}
  .sev-stat-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase}
  .legend-bar{background:#fff;border:1px solid var(--border);border-radius:var(--radius);padding:10px 16px;margin-bottom:14px;display:flex;gap:16px;flex-wrap:wrap;align-items:center}
  .legend-label{font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em}
</style>
</head>
<body>
<div class="report-header">
  <div class="header-top">
    <div class="report-brand">
      <div class="brand-mark">SC</div>
      <div>
        <div class="report-title">Consolidated Security &amp; Compliance Report</div>
        <div class="report-subtitle">Trivy &mdash; All Services Merged &middot; """ + str(len(folders_found)) + """ services scanned</div>
      </div>
    </div>
    <div class="header-meta">
      <div class="meta-item">Source: <span>""" + be_name + """</span></div>
      <div class="meta-item">Generated: <span>""" + generated_at + """</span></div>
    </div>
  </div>
  <div class="metrics-bar">""" + metrics + """</div>
  <div class="nav-tabs">
    <div class="nav-tab active" onclick="switchTab('overview')">Overview</div>
    <div class="nav-tab" onclick="switchTab('vuln')">Vulnerabilities (""" + str(len(vuln_groups)) + """)</div>
    <div class="nav-tab" onclick="switchTab('lic')">Licenses (""" + str(len(lic_groups)) + """)</div>
    <div class="nav-tab" onclick="switchTab('services')">Services (""" + str(len(folders_found)) + """)</div>
  </div>

<div class="content">

  <div class="tab-panel active" id="tab-overview">
    <div class="section-header">
      <span class="section-title">Scan Overview</span>
      <span class="section-desc">Consolidated results across """ + str(len(folders_found)) + """ services</span>
    </div>
    <div class="summary-grid">
      <div class="summary-block">
        <div class="summary-block-header">
          <div class="summary-block-title">License Scan Results</div>
          <div class="summary-block-desc">Unique license findings by severity; package rows stay grouped below</div>
        </div>
        <div class="summary-block-body">""" + lic_stats + """</div>
      </div>
      <div class="summary-block">
        <div class="summary-block-header">
          <div class="summary-block-title">Vulnerability Scan Results</div>
          <div class="summary-block-desc">Unique CVEs by severity; affected services stay grouped below</div>
        </div>
        <div class="summary-block-body">""" + vuln_stats + """</div>
      </div>
    </div>
  </div>

  <div class="tab-panel" id="tab-vuln">
    <div class="section-header">
      <span class="section-title">Vulnerabilities</span>
      <span class="section-desc">""" + str(len(vuln_groups)) + """ package rows &mdash; unique CVEs, severities, fixes, and affected services are grouped per package</span>
    </div>
    <div class="toolbar">
      <input class="search-input" type="text" id="vulnSearch" placeholder="Filter by package, CVE, service..." oninput="filterVuln()">
      <select class="filter-select" id="vulnSevFilter" onchange="filterVuln()">
        <option value="">All Severities</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>UNKNOWN</option>
      </select>
      <button class="btn btn-ghost" onclick="resetVuln()">Reset</button>
      <div class="toolbar-right">
        <button class="btn btn-success" onclick="exportExcel()">Export Excel</button>
        <span class="row-count" id="vulnCount">""" + str(len(vuln_groups)) + """ packages</span>
      </div>
    </div>
    <div class="table-wrap"><div class="table-scroll">
    <table id="vulnTable">
      <thead><tr>
        <th onclick="sortVulnTable(0)">Package <span class="si">&#8645;</span></th>
        <th onclick="sortVulnTable(1)">CVE ID <span class="si">&#8645;</span></th>
        <th onclick="sortVulnTable(2)">Severity <span class="si">&#8645;</span></th>
        <th onclick="sortVulnTable(3)">Installed <span class="si">&#8645;</span></th>
        <th onclick="sortVulnTable(4)">Fix To <span class="si">&#8645;</span></th>
        <th onclick="sortVulnTable(5)">Affected Services / Versions <span class="si">&#8645;</span></th>
      </tr></thead>
      """ + vuln_table_rows() + """
    </table>
    </div></div>
  </div>

  <div class="tab-panel" id="tab-lic">
    <div class="section-header">
      <span class="section-title">Licenses</span>
      <span class="section-desc">""" + str(len(lic_groups)) + """ package rows &mdash; licenses and severities are grouped per package</span>
    </div>
    <div class="legend-bar">
      <span class="legend-label">License Type</span>
      <span>""" + lic_chip('GPL / AGPL') + """ Copyleft &mdash; Replace</span>
      <span>""" + lic_chip('MPL / EPL') + """ Weak copyleft &mdash; Review</span>
      <span>""" + lic_chip('MIT / BSD / ISC') + """ Permissive &mdash; OK</span>
      <span>""" + lic_chip('Apache') + """ Permissive &mdash; OK</span>
      <span>""" + lic_chip('Commercial') + """ Proprietary &mdash; Review</span>
    </div>
    <div class="toolbar">
      <input class="search-input" type="text" id="licSearch" placeholder="Filter by package, license..." oninput="filterLic()">
      <select class="filter-select" id="licSevFilter" onchange="filterLic()">
        <option value="">All Severities</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>UNKNOWN</option>
      </select>
      <button class="btn btn-ghost" onclick="resetLic()">Reset</button>
      <div class="toolbar-right">
        <button class="btn btn-success" onclick="exportExcel()">Export Excel</button>
        <span class="row-count" id="licCount">""" + str(len(lic_groups)) + """ packages</span>
      </div>
    </div>
    <div class="table-wrap"><div class="table-scroll">
    <table id="licTable">
      <thead><tr>
        <th onclick="sortLicTable(0)">Package <span class="si">&#8645;</span></th>
        <th onclick="sortLicTable(1)">License <span class="si">&#8645;</span></th>
        <th onclick="sortLicTable(2)">Severity <span class="si">&#8645;</span></th>
        <th onclick="sortLicTable(3)">Affected Services <span class="si">&#8645;</span></th>
      </tr></thead>
      """ + lic_table_rows() + """
    </table>
    </div></div>
  </div>

  <div class="tab-panel" id="tab-services">
    <div class="section-header">
      <span class="section-title">Scanned Services</span>
      <span class="section-desc">""" + str(len(folders_found)) + """ services included in this report</span>
    </div>
    <div class="table-wrap"><div class="table-scroll">
    <table>
      <thead><tr><th>#</th><th>Service Name</th><th>Dependency Health</th><th>Status</th></tr></thead>
      <tbody>""" + services_rows + """</tbody>
    </table>
    </div></div>
  </div>

</div>

<script>
const VULN_DATA = """ + vuln_json_data + """;
const LIC_DATA  = """ + lic_json_data + """;
const TABS = ['overview','vuln','lic','services'];

function switchTab(tab) {
  TABS.forEach(t => document.getElementById('tab-'+t).classList.toggle('active', t===tab));
  document.querySelectorAll('.nav-tab').forEach((el,i) => el.classList.toggle('active', TABS[i]===tab));
}

function togglePaths(uid, btn) {
  const el = document.getElementById('ph-'+uid);
  if (!el) return;
  const hidden = el.style.display === 'none';
  el.style.display = hidden ? 'block' : 'none';
  btn.textContent = hidden ? 'show less' : ('+ ' + el.children.length + ' more');
}

const sortState = {};
function sortTable(tableId, col) {
  const tbody = document.querySelector('#'+tableId+' tbody');
  const rows  = Array.from(tbody.querySelectorAll('tr.data-row:not(.hidden)'));
  const key   = tableId+col;
  const asc   = sortState[key] = !sortState[key];
  rows.sort((a,b) => {
    const aVal = a.cells[col]?.dataset.value ?? a.cells[col]?.innerText.trim() ?? '';
    const bVal = b.cells[col]?.dataset.value ?? b.cells[col]?.innerText.trim() ?? '';
    const aNum = parseFloat(aVal), bNum = parseFloat(bVal);
    if (!isNaN(aNum) && !isNaN(bNum)) return asc ? aNum-bNum : bNum-aNum;
    return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  });
  rows.forEach(r => tbody.appendChild(r));
  document.querySelectorAll('#'+tableId+' th .si').forEach((el,i) => {
    el.textContent = i===col ? (asc ? '↑' : '↓') : '⇅';
  });
}

function sortVulnTable(col) {
  const table = document.getElementById('vulnTable');
  const groups = Array.from(table.querySelectorAll('tbody.vuln-group'));
  const key = 'vuln' + col;
  const asc = sortState[key] = !sortState[key];
  const sortKeys = ['package', 'cve', 'severity', 'installed', 'fix', 'services'];
  const sortKey = sortKeys[col] || 'package';
  groups.sort((a, b) => {
    const aVal = a.dataset['sort' + sortKey.charAt(0).toUpperCase() + sortKey.slice(1)] || '';
    const bVal = b.dataset['sort' + sortKey.charAt(0).toUpperCase() + sortKey.slice(1)] || '';
    const aNum = parseFloat(aVal), bNum = parseFloat(bVal);
    if (!isNaN(aNum) && !isNaN(bNum)) return asc ? aNum - bNum : bNum - aNum;
    return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  });
  groups.forEach(group => table.appendChild(group));
  document.querySelectorAll('#vulnTable th .si').forEach((el, i) => {
    el.textContent = i === col ? (asc ? '↑' : '↓') : '⇅';
  });
}

function sortLicTable(col) {
  const table = document.getElementById('licTable');
  const groups = Array.from(table.querySelectorAll('tbody.lic-group'));
  const key = 'lic' + col;
  const asc = sortState[key] = !sortState[key];
  const sortKeys = ['package', 'license', 'severity', 'services'];
  const sortKey = sortKeys[col] || 'package';
  groups.sort((a, b) => {
    const aVal = a.dataset['sort' + sortKey.charAt(0).toUpperCase() + sortKey.slice(1)] || '';
    const bVal = b.dataset['sort' + sortKey.charAt(0).toUpperCase() + sortKey.slice(1)] || '';
    const aNum = parseFloat(aVal), bNum = parseFloat(bVal);
    if (!isNaN(aNum) && !isNaN(bNum)) return asc ? aNum - bNum : bNum - aNum;
    return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  });
  groups.forEach(group => table.appendChild(group));
  document.querySelectorAll('#licTable th .si').forEach((el, i) => {
    el.textContent = i === col ? (asc ? '↑' : '↓') : '⇅';
  });
}

function filterVuln() {
  const q = document.getElementById('vulnSearch').value.toLowerCase();
  const sev = document.getElementById('vulnSevFilter').value;
  let c = 0;
  document.querySelectorAll('#vulnTable tbody.vuln-group').forEach(group => {
    const text = group.dataset.search || group.innerText.toLowerCase();
    const severities = group.dataset.severities || group.dataset.severity || '';
    const show = (!q || text.includes(q)) && (!sev || severities.split(',').includes(sev));
    group.classList.toggle('hidden', !show);
    if (show) c++;
  });
  document.getElementById('vulnCount').textContent = c + ' packages';
}

function filterLic() {
  const q   = document.getElementById('licSearch').value.toLowerCase();
  const sev = document.getElementById('licSevFilter').value;
  let c = 0;
  document.querySelectorAll('#licTable tbody.lic-group').forEach(group => {
    const text = group.dataset.search || group.innerText.toLowerCase();
    const severities = group.dataset.severities || group.dataset.severity || '';
    const show = (!q||text.includes(q)) && (!sev||severities.split(',').includes(sev));
    group.classList.toggle('hidden', !show);
    if (show) c++;
  });
  document.getElementById('licCount').textContent = c + ' packages';
}

function resetVuln() { document.getElementById('vulnSearch').value=''; document.getElementById('vulnSevFilter').value=''; filterVuln(); }
function resetLic()  { document.getElementById('licSearch').value=''; document.getElementById('licSevFilter').value=''; filterLic(); }

function colRef(c) {
  let s=''; c++;
  while(c>0){ s=String.fromCharCode(65+(c-1)%26)+s; c=Math.floor((c-1)/26); }
  return s;
}

const SEV = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'];
const SEVERITY_STYLES = {
  CRITICAL: { fill: '8B0000', font: 'FFFFFF' },
  HIGH:     { fill: 'FF0000', font: 'FFFFFF' },
  MEDIUM:   { fill: 'FFD966', font: '000000' },
  LOW:      { fill: '92D050', font: '000000' },
  UNKNOWN:  { fill: '718096', font: 'FFFFFF' }
};
const VULN_SEVERITY_STYLES = {
  CRITICAL: { fill: '8B0000', font: 'FFFFFF' },
  HIGH:     { fill: 'FF0000', font: 'FFFFFF' },
  MEDIUM:   { fill: 'FFC000', font: 'FFFFFF' },
  LOW:      { fill: '92D050', font: 'FFFFFF' },
  UNKNOWN:  { fill: '718096', font: 'FFFFFF' }
};

function sevRank(severity) {
  const idx = SEV.indexOf(severity);
  return idx === -1 ? 99 : idx;
}

function recommendationRank(severity) {
  const idx = ['LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN'].indexOf(String(severity || '').toUpperCase());
  return idx === -1 ? 99 : idx;
}

function recommendedLicense(licenses) {
  return [...licenses].sort((a,b) =>
    recommendationRank(a.severity) - recommendationRank(b.severity)
    || String(a.license || '').localeCompare(String(b.license || ''))
  )[0];
}

function highestSeverityRank(rows) {
  return rows.reduce((best, row) => Math.min(best, sevRank(row.severity)), 99);
}

function sortedPackagesByMergedFirst(byPkg) {
  return Object.keys(byPkg).sort((a, b) => {
    const aMerged = byPkg[a].length > 1 ? 0 : 1;
    const bMerged = byPkg[b].length > 1 ? 0 : 1;
    return aMerged - bMerged
      || highestSeverityRank(byPkg[a]) - highestSeverityRank(byPkg[b])
      || a.localeCompare(b);
  });
}

function applyHeader(ws, totalCols, horizontal = 'center') {
  for (let c=0; c<totalCols; c++) {
    const ref = colRef(c)+'1';
    if (!ws[ref]) continue;
    const current = ws[ref].s || {};
    ws[ref].s = Object.assign({}, current, {
      fill:{ fgColor:{ rgb:'0D1629' } },
      font:{ bold:true, color:{ rgb:'B8CCE0' }, sz:10 },
      alignment:Object.assign({}, current.alignment || {}, { vertical:'center', horizontal, wrapText:true })
    });
  }
  ws['!sheetView'] = [{ state:'frozen', ySplit:1 }];
}

function applySeverityColors(ws, severityCol, styles = SEVERITY_STYLES, horizontal = 'center') {
  if (!ws['!ref']) return;
  const range = XLSX.utils.decode_range(ws['!ref']);
  for (let r = 1; r <= range.e.r; r++) {
    const ref = colRef(severityCol) + (r + 1);
    const cell = ws[ref];
    if (!cell) continue;
    const style = styles[String(cell.v || '').toUpperCase().split('\\n')[0]];
    if (!style) continue;
    const merge = (ws['!merges'] || []).find(m => m.s.c === severityCol && m.s.r === r);
    const endRow = merge ? merge.e.r : r;
    for (let rr = r; rr <= endRow; rr++) {
      const target = ensureCell(ws, rr, severityCol);
      const current = target.s || {};
      target.s = Object.assign({}, current, {
        fill: { patternType: 'solid', fgColor: { rgb: style.fill } },
        font: Object.assign({}, current.font || {}, { bold: true, color: { rgb: style.font } }),
        alignment: Object.assign({}, current.alignment || {}, { horizontal, vertical: 'center', wrapText: true })
      });
    }
  }
}

const VULN_BORDER = {
  top:    { style: 'thin', color: { rgb: '000000' } },
  right:  { style: 'thin', color: { rgb: '000000' } },
  bottom: { style: 'thin', color: { rgb: '000000' } },
  left:   { style: 'thin', color: { rgb: '000000' } }
};

function ensureCell(ws, r, c) {
  const ref = colRef(c) + (r + 1);
  if (!ws[ref]) ws[ref] = { t: 's', v: '' };
  return ws[ref];
}

function mergeColumn(merges, startRow, endRow, col) {
  if (endRow <= startRow) return;
  merges.push({ s: { r: startRow, c: col }, e: { r: endRow, c: col } });
}

function applyVulnSheetStyle(ws, rowCount, colCount) {
  for (let r = 0; r < rowCount; r++) {
    for (let c = 0; c < colCount; c++) {
      const cell = ensureCell(ws, r, c);
      const current = cell.s || {};
      cell.s = Object.assign({}, current, {
        border: VULN_BORDER,
        font: Object.assign({ sz: 11 }, current.font || {}),
        alignment: Object.assign({}, current.alignment || {}, {
          horizontal: 'left',
          vertical: 'center',
          wrapText: true
        })
      });
    }
  }
  applyHeader(ws, colCount, 'left');
}

function joinLines(values) {
  const list = (values || []).map(v => String(v || '').trim()).filter(Boolean);
  return (list.length ? list : ['-']).join('\\n');
}

function joinAffectedInstances(instances, folders) {
  const list = (instances || []).map(item => {
    const service = String(item.service || '-').trim() || '-';
    const version = String(item.version || '-').trim() || '-';
    const fixed = String(item.fixed || '-').trim() || '-';
    return fixed && fixed !== '-' ? `${service}: ${version} → ${fixed}` : `${service}: ${version}`;
  }).filter(Boolean);
  return list.length ? list.join('\\n') : joinLines(folders);
}

function splitLines(value) {
  if (Array.isArray(value)) return value.map(v => String(v || '').trim()).filter(Boolean);
  return String(value || '').split('\\n').map(v => v.trim()).filter(Boolean);
}

function vulnInstanceRows() {
  const rows = [];
  VULN_DATA.forEach(group => {
    (group.vulns || []).forEach(vuln => {
      const instances = vuln.affected_instances && vuln.affected_instances.length
        ? vuln.affected_instances
        : (group.folders || ['-']).map(service => ({ service, version: vuln.version || '-', fixed: vuln.fixed || '-' }));
      instances.forEach(instance => {
        rows.push({
          service: instance.service || '-',
          type: 'Vulnerability',
          severity: vuln.severity || 'UNKNOWN',
          pkg: group.pkg || '-',
          installed: instance.version || vuln.version || '-',
          fixed: instance.fixed || vuln.fixed || '-',
          cve: vuln.cve || '-',
          target: '-',
          title: vuln.title || (vuln.titles || []).join('\\n') || '-'
        });
      });
    });
  });
  return rows;
}

function licenseInstanceRows() {
  const rows = [];
  LIC_DATA.forEach(group => {
    (group.licenses || group.lics || []).forEach(license => {
      const services = splitLines(license.folder).length ? splitLines(license.folder) : (group.folders || ['-']);
      const targets = splitLines(license.target);
      const filepaths = splitLines(license.filepath);
      services.forEach((service, index) => {
        rows.push({
          service: service || '-',
          type: 'License',
          severity: license.severity || 'UNKNOWN',
          pkg: group.pkg || license.pkg || '-',
          installed: '-',
          fixed: '-',
          cve: license.license || '-',
          target: targets[index] || targets[0] || filepaths[index] || filepaths[0] || '-',
          title: license.category || '-'
        });
      });
    });
  });
  return rows;
}

function allInstanceRows() {
  return [...vulnInstanceRows(), ...licenseInstanceRows()].sort((a,b) =>
    String(a.service || '').localeCompare(String(b.service || ''))
    || sevRank(a.severity) - sevRank(b.severity)
    || String(a.pkg || '').localeCompare(String(b.pkg || ''))
    || String(a.cve || '').localeCompare(String(b.cve || ''))
  );
}

function buildSummarySheet() {
  const rows = summaryRows();
  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [38,16,18,14,12,10,10,10,12].map(w => ({ wch: w }));
  applyVulnSheetStyle(ws, rows.length, 9);
  return ws;
}

function buildByServiceSheet() {
  const rows = byServiceRows();
  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [34,16,14,38,18,24,24,34,50].map(w => ({ wch: w }));
  applyVulnSheetStyle(ws, rows.length, 9);
  applySeverityColors(ws, 2, VULN_SEVERITY_STYLES, 'left');
  return ws;
}

function buildAffectedInstancesSheet() {
  const rows = affectedInstanceRowsForExport();
  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [34,16,14,38,18,24,24,34,50].map(w => ({ wch: w }));
  applyVulnSheetStyle(ws, rows.length, 9);
  applySeverityColors(ws, 2, VULN_SEVERITY_STYLES, 'left');
  return ws;
}

function summaryRows() {
  const serviceMap = new Map();
  allInstanceRows().forEach(row => {
    const service = row.service || '-';
    if (!serviceMap.has(service)) {
      serviceMap.set(service, { service, total: 0, vulnerability: 0, license: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 });
    }
    const item = serviceMap.get(service);
    const severity = String(row.severity || 'UNKNOWN').toUpperCase();
    item.total += 1;
    if (row.type === 'Vulnerability') item.vulnerability += 1;
    if (row.type === 'License') item.license += 1;
    item[severity] = (item[severity] || 0) + 1;
  });
  const rows = [['Service','Total Findings','Vulnerabilities','Licenses','Critical','High','Medium','Low','Unknown']];
  [...serviceMap.values()]
    .sort((a,b) => b.CRITICAL - a.CRITICAL || b.HIGH - a.HIGH || b.MEDIUM - a.MEDIUM || b.total - a.total || a.service.localeCompare(b.service))
    .forEach(item => rows.push([item.service, item.total, item.vulnerability, item.license, item.CRITICAL, item.HIGH, item.MEDIUM, item.LOW, item.UNKNOWN]));
  return rows;
}

function byServiceRows() {
  const rows = [['Service','Finding Type','Severity','Package','Installed','Fixed','CVE / License','Target / File','Title / Category']];
  allInstanceRows().forEach(row => rows.push([row.service, row.type, row.severity, row.pkg, row.installed, row.fixed, row.cve, row.target, row.title]));
  return rows;
}

function affectedInstanceRowsForExport() {
  const rows = [['Service','Finding Type','Severity','Package','Installed','Fixed','CVE','Target','Title']];
  vulnInstanceRows().forEach(row => rows.push([row.service, row.type, row.severity, row.pkg, row.installed, row.fixed, row.cve, row.target, row.title]));
  return rows;
}

function vulnerabilityRowsForFallback() {
  const rows = [['Package','CVE ID','Severity','Installed Version','Fix To','Affected Services / Versions']];
  VULN_DATA.forEach(group => {
    (group.vulns || []).forEach(vuln => {
      rows.push([
        group.pkg || '-',
        vuln.cve || '-',
        vuln.severity || 'UNKNOWN',
        joinLines(vuln.versions || [vuln.version || '-']),
        joinLines(vuln.fixed_versions || [vuln.fixed || '-']),
        joinAffectedInstances(vuln.affected_instances || [], group.folders || ['-'])
      ]);
    });
  });
  return rows;
}

function licenseRowsForFallback() {
  const rows = [['Package','License','Severity','ITS khuyến nghị đối với multiple license','Affected Services']];
  LIC_DATA.forEach(group => {
    const lics = group.licenses || group.lics || [];
    const recommended = lics.length > 1 ? recommendedLicense(lics) : null;
    const recommendation = recommended ? `Nên chọn ${recommended.license || '-'} (${recommended.severity || 'UNKNOWN'})` : '';
    lics.forEach(license => rows.push([
      group.pkg || license.pkg || '-',
      license.license || '-',
      license.severity || 'UNKNOWN',
      recommendation,
      joinLines(splitLines(license.folder).length ? splitLines(license.folder) : group.folders || ['-'])
    ]));
  });
  return rows;
}

function excelXmlEscape(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function worksheetXml(name, rows) {
  const body = rows.map(row => '<Row>' + row.map(cell =>
    '<Cell><Data ss:Type="String">' + excelXmlEscape(cell).replace(/\\n/g, '&#10;') + '</Data></Cell>'
  ).join('') + '</Row>').join('');
  return '<Worksheet ss:Name="' + excelXmlEscape(name).slice(0, 31) + '"><Table>' + body + '</Table></Worksheet>';
}

function exportExcelFallback() {
  const sheets = [
    ['Summary', summaryRows()],
    ['By Service', byServiceRows()],
    ['Affected Instances', affectedInstanceRowsForExport()],
    ['Vulnerability', vulnerabilityRowsForFallback()],
    ['License', licenseRowsForFallback()],
  ];
  const xml = '<?xml version="1.0"?><?mso-application progid="Excel.Sheet"?>'
    + '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">'
    + '<Styles><Style ss:ID="Default" ss:Name="Normal"><Alignment ss:Vertical="Center" ss:WrapText="1"/></Style></Styles>'
    + sheets.map(([name, rows]) => worksheetXml(name, rows)).join('')
    + '</Workbook>';
  const blob = new Blob([xml], { type: 'application/vnd.ms-excel;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'consolidated-report.xls';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function buildVulnSheet() {
  const rows = [['Package','CVE ID','Severity','Installed Version','Fix To','Affected Services / Versions']];
  const merges = [];
  const rowHeights = [{ hpt: 20 }];

  VULN_DATA.forEach(g => {
    const cves = [...(g.vulns || [])].sort((a,b) => {
      return sevRank(a.severity)-sevRank(b.severity) || String(a.cve || '').localeCompare(String(b.cve || ''));
    });
    if (cves.length === 0) {
      const rowIndex = rows.length;
      rows.push([g.pkg, '-', '-', '-', '-', joinLines(g.folders)]);
      rowHeights[rowIndex] = { hpt: 24 };
      return;
    }

    const start = rows.length;
    const affectedInstances = cves.flatMap(cv => cv.affected_instances || []);
    const affectedLines = affectedInstances.length ? affectedInstances : (g.folders || ['-']);
    const serviceLinesPerRow = Math.max(1, Math.ceil(affectedLines.length / cves.length));

    cves.forEach((cv, idx) => {
      const versions = cv.versions && cv.versions.length ? cv.versions : [cv.version || '-'];
      const fixes = cv.fixed_versions && cv.fixed_versions.length ? cv.fixed_versions : [cv.fixed || '-'];
      const rowIndex = rows.length;
      rows.push([
        idx === 0 ? g.pkg : '',
        cv.cve || '-',
        cv.severity || 'UNKNOWN',
        joinLines(versions),
        joinLines(fixes),
        idx === 0 ? joinAffectedInstances(affectedInstances, g.folders) : '',
      ]);
      const rowLines = Math.max(1, versions.length, fixes.length, idx === 0 ? serviceLinesPerRow : 1);
      rowHeights[rowIndex] = { hpt: Math.max(18, Math.min(409.5, rowLines * 16)) };
    });

    const end = rows.length - 1;
    [0, 5].forEach(col => mergeColumn(merges, start, end, col));
  });

  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [38,24,14,18,24,35].map(w=>({wch:w}));
  ws['!rows'] = rowHeights;
  ws['!merges'] = merges;
  applyVulnSheetStyle(ws, rows.length, 6);
  applySeverityColors(ws, 2, VULN_SEVERITY_STYLES, 'left');
  return ws;
}

function buildLicSheet() {
  const rows = [['Package','License','Severity','ITS khuyến nghị đối với multiple license','Affected Services']];
  const merges = [];
  const rowHeights = [{ hpt: 20 }];

  LIC_DATA.forEach(g => {
    const lics = [...(g.licenses || g.lics || [])].sort((a,b) =>
      sevRank(a.severity) - sevRank(b.severity)
      || String(a.license || '').localeCompare(String(b.license || ''))
    );
    if (lics.length === 0) {
      const rowIndex = rows.length;
      rows.push([g.pkg, '-', '-', '', joinLines(g.folders)]);
      rowHeights[rowIndex] = { hpt: 24 };
      return;
    }

    const start = rows.length;
    const services = g.folders && g.folders.length ? g.folders : ['-'];
    const recommended = lics.length > 1 ? recommendedLicense(lics) : null;
    const recommendation = recommended ? `Nên chọn ${recommended.license || '-'} (${recommended.severity || 'UNKNOWN'})` : '';

    lics.forEach((lc, idx) => {
      rows.push([
        idx === 0 ? g.pkg : '',
        lc.license || '-',
        lc.severity || 'UNKNOWN',
        idx === 0 ? recommendation : '',
        idx === 0 ? joinLines(services) : '',
      ]);
    });

    const end = rows.length - 1;
    // Merge Package, recommendation, and Affected Services across the group.
    [0, 3, 4].forEach(col => mergeColumn(merges, start, end, col));

    // Merge consecutive rows that share the same severity (col 2),
    // then blank the repeated severity cell so the merge is clean.
    let runStart = start;
    let runSeverity = rows[start][2];
    for (let row = start + 1; row <= end + 1; row++) {
      const severity = row <= end ? rows[row][2] : null;
      if (severity === runSeverity) continue;
      if (row - 1 > runStart) mergeColumn(merges, runStart, row - 1, 2);
      for (let blankRow = runStart + 1; blankRow <= row - 1; blankRow++) {
        rows[blankRow][2] = '';
      }
      runStart = row;
      runSeverity = severity;
    }

    // Row height scaled by the tallest column (license, services).
    const maxLines = Math.max(
      1,
      ...lics.map(lc => Math.max(
        String(lc.license || '').split('\\n').length,
      )),
      services.length
    );
    const perRowHeight = Math.max(16, Math.min(409.5, Math.ceil((maxLines * 16) / lics.length)));
    for (let row = start; row <= end; row++) rowHeights[row] = { hpt: perRowHeight };
  });

  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [38, 34, 14, 44, 35].map(w => ({ wch: w }));
  ws['!rows'] = rowHeights;
  ws['!merges'] = merges;
  applyVulnSheetStyle(ws, rows.length, 5);
  applySeverityColors(ws, 2, SEVERITY_STYLES, 'left');
  return ws;
}

function exportExcel() {
  if (typeof XLSX === 'undefined') {
    exportExcelFallback();
    return;
  }
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, buildSummarySheet(), 'Summary');
  XLSX.utils.book_append_sheet(wb, buildByServiceSheet(), 'By Service');
  XLSX.utils.book_append_sheet(wb, buildAffectedInstancesSheet(), 'Affected Instances');
  XLSX.utils.book_append_sheet(wb, buildVulnSheet(), 'Vulnerability');
  XLSX.utils.book_append_sheet(wb, buildLicSheet(),  'License');
  XLSX.writeFile(wb, 'consolidated-report.xlsx');
}
</script>
</body>
</html>"""

    Path(output_html).write_text(html, encoding="utf-8")
    print("Consolidated report saved: {0}".format(output_html))
    print("  Services scanned   : {0}".format(len(folders_found)))
    print("  Vulnerability package rows : {0}".format(len(vuln_groups)))
    print("  Vulnerability findings     : {0}".format(total_unique_vulns))
    print("  License package rows       : {0}".format(len(lic_groups)))
    print("  License findings           : {0}".format(total_unique_licenses))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m autoscan.reporting.merge_report <services_dir> <output_html>")
        sys.exit(1)
    generate_html(sys.argv[1], sys.argv[2])
