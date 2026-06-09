"""
autoscan.reporting.merge_report
Usage:
    python -m autoscan.reporting.merge_report <services_dir> <output_html>

Merges all report.json found in immediate subfolders of <services_dir>,
generates a consolidated HTML + Excel report with a Paths column.
"""

import json
import sys
import os
from html import escape
from pathlib import Path
from collections import defaultdict
from datetime import datetime

from autoscan.package_names import resolve_package_name

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def get_highest_severity(severities):
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

                lic_rows.append({
                    "folder":   folder_name,
                    "pkg":      pkg_name,
                    "license":  lc.get("Name", ""),
                    "severity": lc.get("Severity", "UNKNOWN"),
                    "category": lc.get("Category", ""),
                    "filepath": lc.get("FilePath", "-") or "-",
                })

    return vuln_rows, lic_rows, folders_found, health_by_folder


def group_vulns(vuln_rows):
    groups = defaultdict(lambda: {"folders": [], "severities": [], "rows": [], "_seen": set()})
    for r in vuln_rows:
        key = r["pkg"]
        g = groups[key]
        if r["folder"] not in g["folders"]:
            g["folders"].append(r["folder"])
        # Dedupe by (CVE, version) per package. A CVE affecting the same package
        # version across multiple folders is the same vulnerability instance,
        # so we keep only one row. Two different versions of the same package
        # hit by the same CVE are kept as separate rows.
        version = (r.get("version") or "").strip() or "-"
        dedup_key = (r.get("cve", ""), version)
        if dedup_key in g["_seen"]:
            continue
        g["_seen"].add(dedup_key)
        g["severities"].append(r["severity"])
        g["rows"].append(r)

    result = []
    for pkg, g in groups.items():
        highest = get_highest_severity(g["severities"])
        result.append({
            "pkg": pkg,
            "severity": highest,
            "versions": sorted({r["version"] for r in g["rows"] if r.get("version")}),
            "fixed_versions": sorted({r["fixed"] for r in g["rows"] if r.get("fixed") and r.get("fixed") != "-"}),
            "folders": sorted(g["folders"]),
            "vulns": sorted(
                g["rows"],
                key=lambda r: (
                    SEVERITY_ORDER.get(r["severity"], 99),
                    str(r.get("cve") or "").lower(),
                    str(r.get("folder") or "").lower(),
                ),
            ),
        })
    result.sort(key=lambda x: (
        0 if len(x["vulns"]) > 1 else 1,
        SEVERITY_ORDER.get(x["severity"], 99),
        x["pkg"].lower(),
    ))
    return result


def group_licenses(lic_rows):
    groups = defaultdict(lambda: {"folders": [], "severities": [], "rows": [], "_seen": set()})
    for r in lic_rows:
        key = r["pkg"]
        g = groups[key]
        if r["folder"] not in g["folders"]:
            g["folders"].append(r["folder"])
        # Dedupe exact (license, severity, category) combos per package so the
        # same row coming from multiple folders is only kept once.
        dedup_key = (r.get("license", ""), r.get("severity", "UNKNOWN"), r.get("category", ""))
        if dedup_key in g["_seen"]:
            continue
        g["_seen"].add(dedup_key)
        g["severities"].append(r["severity"])
        g["rows"].append(r)

    result = []
    for pkg, g in groups.items():
        highest = get_highest_severity(g["severities"])
        license_names = sorted({r["license"] for r in g["rows"] if r.get("license")})
        categories = sorted({r["category"] for r in g["rows"] if r.get("category")})
        action, action_color = get_license_action(highest, ",".join(categories), ",".join(license_names))
        result.append({
            "pkg": pkg,
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
    return '<span class="sev-chip" style="color:{0};border-color:{0}40;background:{0}12">{1}</span>'.format(c, sev)


def lic_chip(name):
    border, bg = get_license_badge_color(name)
    return '<span class="lic-chip" style="color:{0};background:{1};border-color:{0}30">{2}</span>'.format(border, bg, name)


def action_chip(action, color):
    return '<span class="action-chip" style="color:{0};border-color:{0}50;background:{0}10">{1}</span>'.format(color, action)


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
        html += '<div class="path-item">{0}</div>'.format(f)
    if hidden:
        html += '<div class="path-more" onclick="togglePaths({0},this)">+ {1} more</div>'.format(uid, len(hidden))
        html += '<div class="path-hidden" id="ph-{0}" style="display:none">'.format(uid)
        for f in hidden:
            html += '<div class="path-item">{0}</div>'.format(f)
        html += '</div>'
    html += '</div>'
    return html


def generate_html(be_dir, output_html):
    vuln_rows, lic_rows, folders_found, health_by_folder = load_all_reports(be_dir)
    vuln_groups = group_vulns(vuln_rows)
    lic_groups  = group_licenses(lic_rows)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    vuln_sev = defaultdict(int)
    for g in vuln_groups:
        vuln_sev[g["severity"]] += 1

    lic_sev = defaultdict(int)
    for g in lic_groups:
        lic_sev[g["severity"]] += 1

    def vuln_table_rows():
        rows = ""
        sorted_vulns = sorted(vuln_groups, key=lambda x: (
            0 if len(x["vulns"]) > 1 else 1,
            ORDER.get(x["severity"], 99),
            x["pkg"].lower(),
        ))
        for group_index, r in enumerate(sorted_vulns):
            so = ORDER.get(r["severity"], 99)
            group_bg = "grp-even" if (group_index % 2 == 0) else "grp-odd"
            vulns = r["vulns"]
            cve_lines = [
                '<a href="{0}" target="_blank" class="cve-link">{1}</a>'.format(
                    escape(v.get("url", "")),
                    escape(v.get("cve", "")),
                )
                for v in vulns
            ]
            severity_lines = [sev_chip(v["severity"]) for v in vulns]
            version_lines = unique_values(v.get("version", "") for v in vulns)
            fixed_lines = [v.get("fixed") or "-" for v in vulns]
            title_lines = [str(v.get("title") or "")[:120] for v in vulns]
            severity_attr = ",".join(unique_values(v.get("severity", "") for v in vulns))
            rows += '<tr class="data-row lic-grp {8} grp-end" data-severity="{0}" data-severities="{9}" data-pkg="{10}"><td class="pkg-name">{1}</td><td>{2}</td><td data-value="{3}">{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td style="color:#4a5568;font-size:12px;max-width:360px">{11}</td></tr>'.format(
                r["severity"],
                escape(r["pkg"]),
                html_line_stack(cve_lines),
                so,
                html_line_stack(severity_lines),
                line_stack(version_lines),
                line_stack(fixed_lines),
                paths_html(r["folders"]),
                group_bg,
                escape(severity_attr),
                escape(r["pkg"]),
                line_stack(title_lines),
            )
        return rows or '<tr><td colspan="7" class="no-data">No vulnerabilities found.</td></tr>'

    def lic_table_rows():
        rows = ""
        sorted_lics = sorted(lic_groups, key=lambda x: (
            0 if len(x["licenses"]) > 1 else 1,
            ORDER.get(x["severity"], 99),
            x["pkg"].lower(),
        ))
        for group_index, r in enumerate(sorted_lics):
            so = ORDER.get(r["severity"], 99)
            group_bg = "grp-even" if (group_index % 2 == 0) else "grp-odd"
            licenses = r["licenses"]
            # Dedupe by (license, severity, category) tuple so the same combo
            # coming from multiple folders doesn't repeat as chips.
            seen_combo = set()
            unique_licenses = []
            for lic in licenses:
                key = (lic.get("license", ""), lic.get("severity", "UNKNOWN"), lic.get("category", ""))
                if key in seen_combo:
                    continue
                seen_combo.add(key)
                unique_licenses.append(lic)
            license_lines = [lic_chip(lic.get("license", "")) for lic in unique_licenses]
            severity_lines = [sev_chip(lic.get("severity", "UNKNOWN")) for lic in unique_licenses]
            category_lines = [lic.get("category", "") or "-" for lic in unique_licenses]
            action_lines = []
            for lic in unique_licenses:
                action, color = get_license_action(lic.get("severity", ""), lic.get("category", ""), lic.get("license", ""))
                action_lines.append(action_chip(action, color))
            severity_attr = ",".join(unique_values(lic.get("severity", "") for lic in licenses))
            category_attr = ",".join(unique_values(lic.get("category", "") for lic in licenses))
            action_attr = ",".join(unique_values(get_license_action(lic.get("severity", ""), lic.get("category", ""), lic.get("license", ""))[0] for lic in licenses))
            rows += '<tr class="data-row lic-grp {9} grp-end" data-severity="{0}" data-severities="{10}" data-categories="{11}" data-actions="{12}" data-pkg="{8}"><td class="pkg-name">{1}</td><td>{2}</td><td data-value="{3}">{4}</td><td style="font-size:12px;color:#4a5568">{5}</td><td>{6}</td><td>{7}</td></tr>'.format(
                r["severity"],
                escape(r["pkg"]),
                html_line_stack(license_lines),
                so,
                html_line_stack(severity_lines),
                line_stack(category_lines),
                html_line_stack(action_lines),
                paths_html(r["folders"]),
                escape(r["pkg"]),
                group_bg,
                escape(severity_attr),
                escape(category_attr),
                escape(action_attr),
            )
        return rows or '<tr><td colspan="6" class="no-data">No license issues found.</td></tr>'

    def metric_card(label, value, sub, color):
        return '<div class="metric-card"><div class="metric-value" style="color:{0}">{1}</div><div class="metric-label">{2}</div><div class="metric-sub">{3}</div></div>'.format(color, value, label, sub)

    metrics = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        metrics += metric_card(sev, vuln_sev.get(sev, 0), "packages", SEV_COLOR[sev])
    metrics += metric_card("SERVICES", len(folders_found), "scanned", "#3182ce")
    metrics += metric_card("REPLACE",  sum(1 for g in lic_groups if g["action"] == "Replace"), "licenses", "#e53e3e")
    metrics += metric_card("REVIEW",   sum(1 for g in lic_groups if g["action"] == "Review"),  "licenses", "#dd8500")
    metrics += metric_card("OK",       sum(1 for g in lic_groups if g["action"] == "OK"),       "licenses", "#2d9e5f")

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
    lic_json_data  = json.dumps(lic_groups,  ensure_ascii=False).replace('</script>', '<\\/script>').replace('<!--', '<\\!--')

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
          <div class="summary-block-desc">Package rows with license details grouped in each row</div>
        </div>
        <div class="summary-block-body">""" + lic_stats + """</div>
      </div>
      <div class="summary-block">
        <div class="summary-block-header">
          <div class="summary-block-title">Vulnerability Scan Results</div>
          <div class="summary-block-desc">Package rows with CVE details grouped in each row</div>
        </div>
        <div class="summary-block-body">""" + vuln_stats + """</div>
      </div>
    </div>
  </div>

  <div class="tab-panel" id="tab-vuln">
    <div class="section-header">
      <span class="section-title">Vulnerabilities</span>
      <span class="section-desc">""" + str(len(vuln_groups)) + """ package rows &mdash; CVEs, severities, fixes, and titles are grouped per package</span>
    </div>
    <div class="toolbar">
      <input class="search-input" type="text" id="vulnSearch" placeholder="Filter by package, CVE, title..." oninput="filterVuln()">
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
        <th onclick="sortTable('vulnTable',0)">Package <span class="si">&#8645;</span></th>
        <th onclick="sortTable('vulnTable',1)">CVE ID <span class="si">&#8645;</span></th>
        <th onclick="sortTable('vulnTable',2)">Severity <span class="si">&#8645;</span></th>
        <th onclick="sortTable('vulnTable',3)">Installed <span class="si">&#8645;</span></th>
        <th onclick="sortTable('vulnTable',4)">Fix To <span class="si">&#8645;</span></th>
        <th>Affected Services</th>
        <th>Title</th>
      </tr></thead>
      <tbody id="vulnBody">""" + vuln_table_rows() + """</tbody>
    </table>
    </div></div>
  </div>

  <div class="tab-panel" id="tab-lic">
    <div class="section-header">
      <span class="section-title">Licenses</span>
      <span class="section-desc">""" + str(len(lic_groups)) + """ package rows &mdash; licenses, severities, categories, and actions are grouped per package</span>
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
      <select class="filter-select" id="licCatFilter" onchange="filterLic()">
        <option value="">All Categories</option>
        """ + cat_options + """
      </select>
      <select class="filter-select" id="licActFilter" onchange="filterLic()">
        <option value="">All Actions</option>
        <option>Replace</option><option>Review</option><option>OK</option>
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
        <th onclick="sortTable('licTable',0)">Package <span class="si">&#8645;</span></th>
        <th onclick="sortTable('licTable',1)">License <span class="si">&#8645;</span></th>
        <th onclick="sortTable('licTable',2)">Severity <span class="si">&#8645;</span></th>
        <th onclick="sortTable('licTable',3)">Category <span class="si">&#8645;</span></th>
        <th onclick="sortTable('licTable',4)">Action <span class="si">&#8645;</span></th>
        <th>Affected Services</th>
      </tr></thead>
      <tbody id="licBody">""" + lic_table_rows() + """</tbody>
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

function filterVuln() {
  const q = document.getElementById('vulnSearch').value.toLowerCase();
  const sev = document.getElementById('vulnSevFilter').value;
  let c = 0;
  document.querySelectorAll('#vulnBody tr').forEach(tr => {
    const text = (tr.innerText + ' ' + (tr.dataset.pkg || '')).toLowerCase();
    const severities = tr.dataset.severities || tr.dataset.severity || '';
    const show = (!q || text.includes(q)) && (!sev || severities.split(',').includes(sev));
    tr.classList.toggle('hidden', !show);
    if (show) c++;
  });
  document.getElementById('vulnCount').textContent = c + ' packages';
}

function filterLic() {
  const q   = document.getElementById('licSearch').value.toLowerCase();
  const sev = document.getElementById('licSevFilter').value;
  const cat = document.getElementById('licCatFilter').value;
  const act = document.getElementById('licActFilter').value;
  let c = 0;
  document.querySelectorAll('#licBody tr').forEach(tr => {
    // Include data-pkg so rows with blank package cell (grouped) still match search
    const text = (tr.innerText + ' ' + (tr.dataset.pkg || '')).toLowerCase();
    const severities = tr.dataset.severities || tr.dataset.severity || '';
    const categories = (tr.dataset.categories || '').toLowerCase().split(',');
    const actions = (tr.dataset.actions || '').toLowerCase().split(',');
    const show = (!q||text.includes(q)) && (!sev||severities.split(',').includes(sev)) && (!cat||categories.includes(cat.toLowerCase())) && (!act||actions.includes(act.toLowerCase()));
    tr.classList.toggle('hidden', !show);
    if (show) c++;
  });
  document.getElementById('licCount').textContent = c + ' packages';
}

function resetVuln() { document.getElementById('vulnSearch').value=''; document.getElementById('vulnSevFilter').value=''; filterVuln(); }
function resetLic()  { document.getElementById('licSearch').value=''; document.getElementById('licSevFilter').value=''; document.getElementById('licCatFilter').value=''; document.getElementById('licActFilter').value=''; filterLic(); }

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
  LOW:      { fill: '92D050', font: '000000' }
};

function sevRank(severity) {
  const idx = SEV.indexOf(severity);
  return idx === -1 ? 99 : idx;
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

function applyHeader(ws, totalCols) {
  for (let c=0; c<totalCols; c++) {
    const ref = colRef(c)+'1';
    if (!ws[ref]) continue;
    ws[ref].s = {
      fill:{ fgColor:{ rgb:'0D1629' } },
      font:{ bold:true, color:{ rgb:'B8CCE0' }, sz:10 },
      alignment:{ vertical:'center', horizontal:'center', wrapText:true }
    };
  }
  ws['!sheetView'] = [{ state:'frozen', ySplit:1 }];
}

function applySeverityColors(ws, severityCol) {
  if (!ws['!ref']) return;
  const range = XLSX.utils.decode_range(ws['!ref']);
  for (let r = 1; r <= range.e.r; r++) {
    const ref = colRef(severityCol) + (r + 1);
    const cell = ws[ref];
    if (!cell) continue;
    const style = SEVERITY_STYLES[String(cell.v || '').toUpperCase().split('\\n')[0]];
    if (!style) continue;
    const current = cell.s || {};
    cell.s = Object.assign({}, current, {
      fill: { patternType: 'solid', fgColor: { rgb: style.fill } },
      font: Object.assign({}, current.font || {}, { bold: true, color: { rgb: style.font } }),
      alignment: Object.assign({}, current.alignment || {}, { horizontal: 'center', vertical: 'center' })
    });
  }
}

// Apply vertical-center alignment to a merged cell so the value sits in the middle
function styleMergedCell(ws, col, startRow, endRow) {
  const ref = colRef(col) + (startRow + 1);
  if (ws[ref]) {
    ws[ref].s = Object.assign({}, ws[ref].s, {
      alignment: { vertical: 'center', wrapText: false }
    });
  }
}

function buildVulnSheet() {
  const rows = [['Package','CVE ID','Severity','Installed Version','Fix To','Affected Services','Title']];
  const merges = [];
  VULN_DATA.forEach(g => {
    const cves = [...g.vulns].sort((a,b) => sevRank(a.severity)-sevRank(b.severity));
    const folders = g.folders.join('\\n');
    if (cves.length === 0) {
      rows.push([g.pkg, '-', '-', '-', '-', folders, '-']);
      return;
    }
    const firstRow = rows.length; // 0-indexed
    cves.forEach((cv, idx) => {
      rows.push([
        idx === 0 ? g.pkg : '',
        cv.cve || '-',
        cv.severity || '-',
        cv.version || '-',
        cv.fixed || '-',
        idx === 0 ? folders : '',
        cv.title || '-',
      ]);
    });
    const lastRow = rows.length - 1;
    if (lastRow > firstRow) {
      // Merge Package (col 0) and Affected Services (col 5) across the group
      merges.push({ s: { r: firstRow, c: 0 }, e: { r: lastRow, c: 0 } });
      merges.push({ s: { r: firstRow, c: 5 }, e: { r: lastRow, c: 5 } });
    }
  });

  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [38,24,14,18,24,35,60].map(w=>({wch:w}));
  ws['!merges'] = merges;
  applyHeader(ws, 7);
  applySeverityColors(ws, 2);
  // Re-style merged Package/Affected-Services cells so the value sits centered
  merges.forEach(m => {
    if (m.s.c !== 0 && m.s.c !== 5) return;
    const ref = colRef(m.s.c) + (m.s.r + 1);
    if (ws[ref]) {
      ws[ref].s = Object.assign({}, ws[ref].s, {
        alignment: { vertical: 'center', wrapText: true }
      });
    }
  });
  return ws;
}

function buildLicSheet() {
  const rows = [['Package','License','Severity','Category','Action','Affected Services']];
  const merges = [];
  LIC_DATA.forEach(g => {
    const lics = [...g.licenses].sort((a,b) => sevRank(a.severity)-sevRank(b.severity));
    const folders = g.folders.join('\\n');
    if (lics.length === 0) {
      rows.push([g.pkg, '-', '-', '-', '-', folders]);
      return;
    }
    const firstRow = rows.length;
    lics.forEach((lc, idx) => {
      const sev = String(lc.severity || '').toUpperCase();
      const cat = String(lc.category || '').toLowerCase();
      const name = String(lc.license || '');
      let action = 'OK';
      if (['CRITICAL','HIGH'].includes(sev) || cat.includes('restricted') || cat.includes('forbidden')) action = 'Replace';
      else if (['MEDIUM','LOW'].includes(sev) || cat.includes('reciprocal') || cat.includes('notice')) action = 'Review';
      else if (name.startsWith('LicenseRef-') || sev === 'UNKNOWN' || !cat || cat === 'unknown') action = 'Review';
      rows.push([
        idx === 0 ? g.pkg : '',
        lc.license || '-',
        lc.severity || 'UNKNOWN',
        lc.category || '-',
        action,
        idx === 0 ? folders : '',
      ]);
    });
    const lastRow = rows.length - 1;
    if (lastRow > firstRow) {
      merges.push({ s: { r: firstRow, c: 0 }, e: { r: lastRow, c: 0 } });
      merges.push({ s: { r: firstRow, c: 5 }, e: { r: lastRow, c: 5 } });
    }
  });

  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [38,34,14,20,16,35].map(w=>({wch:w}));
  ws['!merges'] = merges;
  applyHeader(ws, 6);
  applySeverityColors(ws, 2);
  merges.forEach(m => {
    if (m.s.c !== 0 && m.s.c !== 5) return;
    const ref = colRef(m.s.c) + (m.s.r + 1);
    if (ws[ref]) {
      ws[ref].s = Object.assign({}, ws[ref].s, {
        alignment: { vertical: 'center', wrapText: true }
      });
    }
  });
  return ws;
}

function exportExcel() {
  const wb = XLSX.utils.book_new();
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
    print("  License package rows       : {0}".format(len(lic_groups)))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m autoscan.reporting.merge_report <services_dir> <output_html>")
        sys.exit(1)
    generate_html(sys.argv[1], sys.argv[2])
