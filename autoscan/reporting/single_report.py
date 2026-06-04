import json
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime

def get_highest_severity(severities):
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return min(severities, key=lambda s: SEVERITY_ORDER.get(s, 99))

def get_recommended_fix(fixed_versions_list):
    all_versions = []
    for fv in fixed_versions_list:
        if fv and fv != "-":
            for v in fv.split(","):
                v = v.strip()
                if v:
                    all_versions.append(v)
    if not all_versions:
        return "-"
    def version_key(v):
        try:
            return tuple(int(x) for x in v.split("."))
        except:
            return (0,)
    return max(all_versions, key=version_key)

def get_license_action(severity, category):
    category = (category or "").lower()
    severity = (severity or "").upper()
    if severity in ("CRITICAL", "HIGH") or "restricted" in category or "forbidden" in category:
        return ("Replace", "#e53e3e")
    elif severity == "MEDIUM" or "reciprocal" in category:
        return ("Review", "#dd8500")
    elif severity == "LOW" or "notice" in category:
        return ("Review", "#dd8500")
    else:
        return ("OK", "#2d9e5f")

def get_license_badge_color(license_name):
    name = (license_name or "").upper()
    if any(x in name for x in ["GPL", "AGPL", "LGPL", "EUPL", "CDDL", "SSPL"]):
        return ("#e53e3e", "#fff0f0")
    elif any(x in name for x in ["MPL", "EPL", "OSL", "CPL"]):
        return ("#dd8500", "#fff8e6")
    elif any(x in name for x in ["MIT", "BSD", "ISC", "WTFPL", "UNLICENSE", "CC0", "ZLIB"]):
        return ("#2d9e5f", "#f0fff6")
    elif any(x in name for x in ["APACHE", "PSF", "PYTHON"]):
        return ("#2b6cb0", "#ebf4ff")
    elif any(x in name for x in ["COMMERCIAL", "PROPRIETARY"]):
        return ("#6b46c1", "#f5f0ff")
    else:
        return ("#4a5568", "#f7fafc")

def generate_html(report_path="report.json", output_path="report.html"):
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("Results", [])
    vuln_rows = []
    license_rows = []
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    for result in results:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            vuln_rows.append({
                "target": target,
                "pkg": v.get("PkgName", ""),
                "version": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion", "-"),
                "cve": v.get("VulnerabilityID", ""),
                "severity": v.get("Severity", "UNKNOWN"),
                "title": v.get("Title", ""),
                "url": f"https://avd.aquasec.com/nvd/{v.get('VulnerabilityID','').lower()}"
            })
        for lic in result.get("Licenses") or []:
            license_rows.append({
                "target": target,
                "pkg": lic.get("PkgName", ""),
                "license": lic.get("Name", ""),
                "severity": lic.get("Severity", "UNKNOWN"),
                "category": lic.get("Category", ""),
                "filepath": lic.get("FilePath", "-"),
            })

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    def merged_first_group_key(row, count_key, severity_key, *text_keys):
        merged_rank = 0 if row.get(count_key, 0) > 1 else 1
        text_values = tuple(str(row.get(k, "")).lower() for k in text_keys)
        return (merged_rank, SEVERITY_ORDER.get(row.get(severity_key), 99), *text_values)

    vuln_rows.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    license_rows.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    # ── GROUP VULNS ──
    vuln_grouped = defaultdict(list)
    for v in vuln_rows:
        vuln_grouped[(v["pkg"], v["version"], v["target"])].append(v)

    pkg_groups = []
    for (pkg, version, target), cves in vuln_grouped.items():
        severities = [c["severity"] for c in cves]
        highest = get_highest_severity(severities)
        fix_to = get_recommended_fix([c["fixed"] for c in cves])
        sev_counts = {}
        for s in severities:
            sev_counts[s] = sev_counts.get(s, 0) + 1
        pkg_groups.append({
            "pkg": pkg, "version": version, "target": target,
            "fix_to": fix_to, "highest_severity": highest,
            "cve_count": len(cves), "sev_counts": sev_counts, "cves": cves,
        })
    pkg_groups.sort(key=lambda x: merged_first_group_key(x, "cve_count", "highest_severity", "pkg", "target"))

    vuln_group_sizes = {
        (g["pkg"], g["version"], g["target"]): g["cve_count"]
        for g in pkg_groups
    }
    vuln_rows.sort(key=lambda x: (
        0 if vuln_group_sizes.get((x["pkg"], x["version"], x["target"]), 0) > 1 else 1,
        SEVERITY_ORDER.get(x["severity"], 99),
        x["pkg"].lower(),
        x["cve"].lower(),
        x["target"].lower(),
    ))

    # ── GROUP LICENSES ──
    lic_grouped = defaultdict(list)
    for lic in license_rows:
        lic_grouped[(lic["pkg"], lic["target"])].append(lic)

    lic_groups = []
    for (pkg, target), lics in lic_grouped.items():
        severities = [l["severity"] for l in lics]
        highest = get_highest_severity(severities)
        license_names = list(dict.fromkeys(l["license"] for l in lics))
        categories = list(dict.fromkeys(l["category"] for l in lics if l["category"]))
        action, action_color = get_license_action(highest, lics[0].get("category", ""))
        lic_groups.append({
            "pkg": pkg, "target": target,
            "highest_severity": highest,
            "license_names": license_names,
            "categories": categories,
            "action": action, "action_color": action_color,
            "lic_count": len(lics),
            "lics": lics,
        })
    lic_groups.sort(key=lambda x: merged_first_group_key(x, "lic_count", "highest_severity", "pkg", "target"))

    lic_group_sizes = {
        (g["pkg"], g["target"]): g["lic_count"]
        for g in lic_groups
    }
    license_rows.sort(key=lambda x: (
        0 if lic_group_sizes.get((x["pkg"], x["target"]), 0) > 1 else 1,
        SEVERITY_ORDER.get(x["severity"], 99),
        x["pkg"].lower(),
        x["license"].lower(),
        x["target"].lower(),
    ))

    # ── SEVERITY STYLES ──
    sev_style = {
        "CRITICAL": ("--sev-critical", "#e53e3e"),
        "HIGH":     ("--sev-high",     "#dd6b20"),
        "MEDIUM":   ("--sev-medium",   "#dd8500"),
        "LOW":      ("--sev-low",      "#2d9e5f"),
        "UNKNOWN":  ("--sev-unknown",  "#718096"),
    }

    def sev_chip(severity):
        _, color = sev_style.get(severity, ("", "#718096"))
        return f'<span class="sev-chip" style="color:{color};border-color:{color}40;background:{color}12">{severity}</span>'

    def sev_dot(severity):
        _, color = sev_style.get(severity, ("", "#718096"))
        return f'<span class="sev-dot" style="background:{color}" title="{severity}"></span>'

    def lic_chip(name):
        border_color, bg = get_license_badge_color(name)
        return f'<span class="lic-chip" style="color:{border_color};background:{bg};border-color:{border_color}30">{name}</span>'

    def action_chip(action, color):
        return f'<span class="action-chip" style="color:{color};border-color:{color}50;background:{color}10">{action}</span>'

    def breakdown_bar(sev_counts):
        total = sum(sev_counts.values())
        if not total:
            return ""
        colors = {"CRITICAL": "#e53e3e", "HIGH": "#dd6b20", "MEDIUM": "#dd8500", "LOW": "#2d9e5f", "UNKNOWN": "#718096"}
        segments = ""
        chips = ""
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            c = sev_counts.get(s, 0)
            if c:
                pct = (c / total) * 100
                segments += f'<div style="width:{pct:.1f}%;background:{colors[s]};height:100%"></div>'
                chips += f'<span style="color:{colors[s]};font-size:11px;font-weight:600">{s[0]}:{c}</span>'
        return f'<div style="display:flex;flex-direction:column;gap:4px"><div style="display:flex;height:4px;border-radius:2px;overflow:hidden;width:120px;background:#e2e8f0">{segments}</div><div style="display:flex;gap:6px">{chips}</div></div>'

    # ── VULN SUMMARY ROWS ──
    vuln_summary_rows = ""
    for i, g in enumerate(pkg_groups):
        sev_order = SEVERITY_ORDER.get(g["highest_severity"], 99)
        fix_display = f'<span class="fix-version">{g["fix_to"]}</span>' if g["fix_to"] != "-" else '<span style="color:#a0aec0;font-size:12px">No fix available</span>'
        cve_sub = ""
        for cv in g["cves"]:
            cve_sub += f"""<tr class="sub-row detail-vuln-{i}">
                <td style="padding-left:40px">
                    <a href="{cv['url']}" target="_blank" class="cve-link">{cv['cve']}</a>
                </td>
                <td></td><td></td>
                <td>{sev_chip(cv['severity'])}</td>
                <td></td>
                <td style="color:#4a5568;font-size:12px">{cv['title'][:80]}{'...' if len(cv['title'])>80 else ''}</td>
                <td></td>
            </tr>"""
        vuln_summary_rows += f"""
        <tr class="data-row pkg-row" data-idx="{i}" data-severity="{g['highest_severity']}" data-sev-order="{sev_order}" onclick="toggleDetail('vuln',{i},this)">
            <td><div style="display:flex;align-items:center;gap:8px"><span class="expand-btn" id="icon-vuln-{i}">+</span><span class="pkg-name">{g['pkg']}</span></div></td>
            <td><span class="version-tag">{g['version']}</span></td>
            <td>{fix_display}</td>
            <td data-value="{sev_order}">{sev_chip(g['highest_severity'])}</td>
            <td>{breakdown_bar(g['sev_counts'])}</td>
            <td><span class="count-pill">{g['cve_count']}</span></td>
            <td class="dim-text">{g['target']}</td>
        </tr>{cve_sub}"""

    # ── VULN DETAIL ROWS ──
    def vuln_detail_rows():
        rows = ""
        for r in vuln_rows:
            sev_order = SEVERITY_ORDER.get(r["severity"], 99)
            rows += f"""<tr class="data-row" data-severity="{r['severity']}">
                <td class="pkg-name">{r['pkg']}</td>
                <td><span class="version-tag">{r['version']}</span></td>
                <td><span class="fix-version">{r['fixed']}</span></td>
                <td><a href="{r['url']}" target="_blank" class="cve-link">{r['cve']}</a></td>
                <td data-value="{sev_order}">{sev_chip(r['severity'])}</td>
                <td style="color:#4a5568;max-width:360px">{r['title']}</td>
                <td class="dim-text">{r['target']}</td>
            </tr>"""
        return rows

    # ── LICENSE SUMMARY ROWS ──
    lic_summary_rows = ""
    for i, g in enumerate(lic_groups):
        sev_order = SEVERITY_ORDER.get(g["highest_severity"], 99)
        lic_chips_html = " ".join(lic_chip(n) for n in g["license_names"])
        cat_str = ", ".join(g["categories"]) if g["categories"] else "-"
        act_html = action_chip(g["action"], g["action_color"])
        lic_sub = ""
        for lc in g["lics"]:
            lc_sev_order = SEVERITY_ORDER.get(lc["severity"], 99)
            lc_action, lc_color = get_license_action(lc["severity"], lc.get("category", ""))
            lc_border, lc_bg = get_license_badge_color(lc["license"])
            lic_sub += f"""<tr class="sub-row detail-lic-{i}">
                <td style="padding-left:40px">{lic_chip(lc['license'])}</td>
                <td data-value="{lc_sev_order}">{sev_chip(lc['severity'])}</td>
                <td style="color:#4a5568;font-size:12px">{lc.get('category','-')}</td>
                <td>{action_chip(lc_action, lc_color)}</td>
                <td class="dim-text" colspan="3">{lc.get('filepath','-')}</td>
            </tr>"""
        lic_summary_rows += f"""
        <tr class="data-row lic-row" data-idx="{i}" data-severity="{g['highest_severity']}" data-sev-order="{sev_order}" onclick="toggleDetail('lic',{i},this)">
            <td><div style="display:flex;align-items:center;gap:8px"><span class="expand-btn" id="icon-lic-{i}">+</span><span class="pkg-name">{g['pkg']}</span></div></td>
            <td style="max-width:280px">{lic_chips_html}</td>
            <td data-value="{sev_order}">{sev_chip(g['highest_severity'])}</td>
            <td style="color:#4a5568;font-size:12px">{cat_str}</td>
            <td>{act_html}</td>
            <td><span class="count-pill">{g['lic_count']}</span></td>
            <td class="dim-text">{g['target']}</td>
        </tr>{lic_sub}"""

    # ── LICENSE DETAIL ROWS ──
    def lic_detail_rows():
        rows = ""
        for r in license_rows:
            sev_order = SEVERITY_ORDER.get(r["severity"], 99)
            act, act_color = get_license_action(r["severity"], r.get("category", ""))
            rows += f"""<tr class="data-row" data-severity="{r['severity']}" data-category="{r.get('category','')}">
                <td class="pkg-name">{r['pkg']}</td>
                <td>{lic_chip(r['license'])}</td>
                <td data-value="{sev_order}">{sev_chip(r['severity'])}</td>
                <td style="color:#4a5568;font-size:12px">{r.get('category','-')}</td>
                <td>{action_chip(act, act_color)}</td>
                <td class="dim-text" style="font-size:11px">{r.get('filepath','-')}</td>
                <td class="dim-text">{r['target']}</td>
            </tr>"""
        return rows

    # ── METRICS ──
    sev_counts_total = {}
    vuln_sev = {}
    for r in vuln_rows:
        sev_counts_total[r["severity"]] = sev_counts_total.get(r["severity"], 0) + 1
        vuln_sev[r["severity"]] = vuln_sev.get(r["severity"], 0) + 1

    lic_sev = {}
    for r in license_rows:
        lic_sev[r["severity"]] = lic_sev.get(r["severity"], 0) + 1

    action_counts = {"Replace": 0, "Review": 0, "OK": 0}
    for g in lic_groups:
        action_counts[g["action"]] = action_counts.get(g["action"], 0) + 1

    # ── METRIC CARDS ──
    def metric_card(label, value, sub, accent):
        return f"""<div class="metric-card">
            <div class="metric-value" style="color:{accent}">{value}</div>
            <div class="metric-label">{label}</div>
            <div class="metric-sub">{sub}</div>
        </div>"""

    metrics_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sev_counts_total.get(sev, 0)
        _, color = sev_style.get(sev, ("", "#718096"))
        metrics_html += metric_card(sev, count, "vulnerabilities", color)
    metrics_html += metric_card("PACKAGES", len(pkg_groups), "affected", "#3182ce")
    metrics_html += metric_card("REPLACE", action_counts["Replace"], "licenses", "#e53e3e")
    metrics_html += metric_card("REVIEW", action_counts["Review"], "licenses", "#dd8500")
    metrics_html += metric_card("COMPLIANT", action_counts["OK"], "licenses", "#2d9e5f")

    all_categories = sorted(set(l["category"] for l in license_rows if l.get("category")))
    cat_options = "\n".join(f'<option value="{c}">{c}</option>' for c in all_categories)

    pkg_groups_json = json.dumps([{
        "pkg": g["pkg"], "version": g["version"], "fix_to": g["fix_to"],
        "highest_severity": g["highest_severity"], "cve_count": g["cve_count"],
        "target": g["target"],
        "cves": [{"cve": c["cve"], "severity": c["severity"], "title": c["title"], "fixed": c["fixed"]} for c in g["cves"]]
    } for g in pkg_groups], ensure_ascii=False).replace('</script>', '<\\/script>').replace('<!--', '<\\!--')

    lic_groups_json = json.dumps([{
        "pkg": g["pkg"], "target": g["target"],
        "highest_severity": g["highest_severity"],
        "license_names": g["license_names"],
        "categories": g["categories"],
        "action": g["action"],
        "lic_count": g["lic_count"],
        "lics": g["lics"],
    } for g in lic_groups], ensure_ascii=False).replace('</script>', '<\\/script>').replace('<!--', '<\\!--')

    vuln_json = json.dumps(vuln_rows, ensure_ascii=False).replace('</script>', '<\\/script>').replace('<!--', '<\\!--')
    lic_json  = json.dumps(license_rows, ensure_ascii=False).replace('</script>', '<\\/script>').replace('<!--', '<\\!--')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security & Compliance Report</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/xlsx-js-style@1.2.0/dist/xlsx.bundle.js"></script>
<style>
  :root {{
    --navy-950: #0a0f1e;
    --navy-900: #0d1629;
    --navy-800: #112240;
    --navy-700: #1a3356;
    --navy-600: #234b7a;
    --navy-100: #e8eef7;
    --navy-50:  #f0f4fa;
    --slate-800: #1e2a3a;
    --slate-700: #2d3d52;
    --slate-600: #3d5068;
    --slate-400: #8fa3be;
    --slate-300: #b8cce0;
    --slate-200: #d4e2f0;
    --slate-100: #eaf1f8;
    --slate-50:  #f5f8fc;
    --white: #ffffff;
    --text-primary: #1a2332;
    --text-secondary: #4a5e72;
    --text-muted: #8fa3be;
    --border: #dde8f2;
    --border-strong: #c4d4e5;
    --sev-critical: #e53e3e;
    --sev-high: #dd6b20;
    --sev-medium: #dd8500;
    --sev-low: #2d9e5f;
    --sev-unknown: #718096;
    --accent: #2563eb;
    --radius: 4px;
    --radius-lg: 8px;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'IBM Plex Sans', -apple-system, sans-serif;
    background: var(--slate-50);
    color: var(--text-primary);
    font-size: 13px;
    line-height: 1.5;
  }}

  /* ── HEADER ── */
  .report-header {{
    background: linear-gradient(135deg, var(--navy-950) 0%, var(--navy-800) 60%, var(--navy-700) 100%);
    padding: 0;
    position: relative;
    overflow: hidden;
  }}
  .report-header::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background:
      repeating-linear-gradient(90deg, transparent, transparent 80px, rgba(255,255,255,0.015) 80px, rgba(255,255,255,0.015) 81px),
      repeating-linear-gradient(0deg, transparent, transparent 80px, rgba(255,255,255,0.015) 80px, rgba(255,255,255,0.015) 81px);
    pointer-events: none;
  }}

  .header-top {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 24px 40px 20px;
    border-bottom: 1px solid rgba(255,255,255,0.08);
  }}

  .report-brand {{
    display: flex;
    align-items: center;
    gap: 14px;
  }}

  .brand-mark {{
    width: 36px;
    height: 36px;
    background: linear-gradient(135deg, #2563eb, #1d4ed8);
    border-radius: var(--radius);
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 14px;
    font-weight: 600;
    color: white;
    letter-spacing: -1px;
    flex-shrink: 0;
  }}

  .report-title {{
    font-size: 15px;
    font-weight: 600;
    color: var(--white);
    letter-spacing: 0.01em;
  }}

  .report-subtitle {{
    font-size: 11px;
    color: var(--slate-400);
    font-weight: 400;
    margin-top: 1px;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }}

  .header-meta {{
    text-align: right;
  }}

  .meta-item {{
    font-size: 11px;
    color: var(--slate-400);
    font-family: 'IBM Plex Mono', monospace;
  }}

  .meta-item span {{
    color: var(--slate-300);
    font-weight: 500;
  }}

  /* ── METRICS ── */
  .metrics-bar {{
    display: flex;
    padding: 20px 40px 24px;
    gap: 0;
    overflow-x: auto;
  }}

  .metric-card {{
    flex: 1;
    min-width: 90px;
    padding: 12px 20px;
    border-right: 1px solid rgba(255,255,255,0.07);
    position: relative;
  }}

  .metric-card:last-child {{ border-right: none; }}

  .metric-value {{
    font-size: 28px;
    font-weight: 700;
    font-family: 'IBM Plex Mono', monospace;
    line-height: 1;
    margin-bottom: 4px;
  }}

  .metric-label {{
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: rgba(255,255,255,0.5);
    margin-bottom: 1px;
  }}

  .metric-sub {{
    font-size: 10px;
    color: rgba(255,255,255,0.3);
  }}

  /* ── NAV TABS ── */
  .nav-tabs {{
    display: flex;
    padding: 0 40px;
    gap: 2px;
    border-top: 1px solid rgba(255,255,255,0.06);
  }}

  .nav-tab {{
    padding: 12px 20px;
    font-size: 12px;
    font-weight: 500;
    color: var(--slate-400);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.15s;
    letter-spacing: 0.02em;
    user-select: none;
    white-space: nowrap;
  }}

  .nav-tab:hover {{ color: var(--slate-200); }}

  .nav-tab.active {{
    color: var(--white);
    border-bottom-color: #3b82f6;
    font-weight: 600;
  }}

  /* ── CONTENT ── */
  .content {{
    max-width: 1600px;
    margin: 0 auto;
    padding: 28px 40px 48px;
  }}

  .tab-panel {{ display: none; }}
  .tab-panel.active {{ display: block; }}

  /* ── TOOLBAR ── */
  .toolbar {{
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 14px;
  }}

  .search-input {{
    padding: 7px 12px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    font-size: 12px;
    font-family: 'IBM Plex Sans', sans-serif;
    outline: none;
    background: var(--white);
    color: var(--text-primary);
    min-width: 200px;
    transition: border-color 0.15s;
  }}

  .search-input:focus {{ border-color: var(--accent); }}

  .filter-select {{
    padding: 7px 10px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    font-size: 12px;
    font-family: 'IBM Plex Sans', sans-serif;
    outline: none;
    background: var(--white);
    color: var(--text-secondary);
    cursor: pointer;
  }}

  .btn {{
    padding: 7px 14px;
    border: none;
    border-radius: var(--radius);
    font-size: 12px;
    font-family: 'IBM Plex Sans', sans-serif;
    font-weight: 500;
    cursor: pointer;
    transition: opacity 0.15s, background 0.15s;
    white-space: nowrap;
  }}

  .btn:hover {{ opacity: 0.85; }}
  .btn-primary  {{ background: #2563eb; color: #fff; }}
  .btn-success  {{ background: #1a7a4a; color: #fff; }}
  .btn-ghost    {{ background: var(--slate-100); color: var(--text-secondary); border: 1px solid var(--border); }}
  .btn-expand   {{ background: var(--navy-800); color: var(--slate-200); border: 1px solid var(--navy-600); }}

  .toolbar-right {{ margin-left: auto; display: flex; gap: 8px; align-items: center; }}
  .row-count {{ font-size: 12px; color: var(--text-muted); font-family: 'IBM Plex Mono', monospace; }}

  /* ── INFO BANNER ── */
  .info-banner {{
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-left: 3px solid #3b82f6;
    border-radius: var(--radius);
    padding: 9px 14px;
    font-size: 12px;
    color: #1e40af;
    margin-bottom: 14px;
  }}

  /* ── LEGEND ── */
  .legend-bar {{
    background: var(--white);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 10px 16px;
    margin-bottom: 14px;
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    align-items: center;
  }}

  .legend-label {{
    font-size: 11px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }}

  .legend-item {{
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-secondary);
  }}

  /* ── TABLE ── */
  .table-wrap {{
    background: var(--white);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }}

  .table-scroll {{ overflow-x: auto; }}

  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
  }}

  thead {{
    background: var(--navy-900);
  }}

  thead th {{
    padding: 10px 14px;
    text-align: left;
    font-size: 10.5px;
    font-weight: 600;
    color: var(--slate-400);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
    border-right: 1px solid rgba(255,255,255,0.05);
    transition: color 0.15s;
  }}

  thead th:last-child {{ border-right: none; }}
  thead th:hover {{ color: var(--slate-200); }}

  .si {{
    margin-left: 4px;
    opacity: 0.4;
    font-size: 10px;
  }}

  tbody tr {{ border-bottom: 1px solid var(--border); }}
  tbody tr:last-child {{ border-bottom: none; }}

  .data-row {{ cursor: default; }}
  .data-row:hover td {{ background: var(--slate-50); }}

  .pkg-row {{ cursor: pointer; }}
  .lic-row {{ cursor: pointer; }}

  .sub-row td {{ background: #fafcff; }}
  .sub-row:hover td {{ background: #f0f6ff; }}

  td {{
    padding: 10px 14px;
    color: var(--text-primary);
    vertical-align: middle;
  }}

  tr.hidden {{ display: none !important; }}

  /* ── COMPONENTS ── */
  .pkg-name {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 12px;
    font-weight: 600;
    color: var(--navy-800);
  }}

  .cve-link {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 12px;
    color: #2563eb;
    text-decoration: none;
    font-weight: 500;
  }}

  .cve-link:hover {{ text-decoration: underline; }}

  .version-tag {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    background: var(--slate-100);
    color: var(--text-secondary);
    padding: 2px 7px;
    border-radius: var(--radius);
    border: 1px solid var(--border);
    display: inline-block;
  }}

  .fix-version {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    background: #f0fff6;
    color: #1a7a4a;
    padding: 2px 7px;
    border-radius: var(--radius);
    border: 1px solid #c6f6d5;
    display: inline-block;
  }}

  .sev-chip {{
    display: inline-block;
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 0.05em;
    padding: 2px 8px;
    border-radius: var(--radius);
    border: 1px solid;
    font-family: 'IBM Plex Sans', sans-serif;
  }}

  .lic-chip {{
    display: inline-block;
    font-size: 11px;
    font-weight: 500;
    padding: 2px 8px;
    border-radius: var(--radius);
    border: 1px solid;
    margin: 2px 2px 2px 0;
    white-space: nowrap;
  }}

  .action-chip {{
    display: inline-block;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    padding: 2px 10px;
    border-radius: var(--radius);
    border: 1px solid;
    text-transform: uppercase;
  }}

  .count-pill {{
    display: inline-block;
    background: var(--navy-800);
    color: var(--slate-300);
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 9px;
    border-radius: 12px;
  }}

  .expand-btn {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    background: var(--slate-100);
    color: var(--text-muted);
    border: 1px solid var(--border-strong);
    border-radius: 3px;
    font-size: 12px;
    font-weight: 700;
    line-height: 1;
    flex-shrink: 0;
    transition: background 0.15s;
    font-family: 'IBM Plex Mono', monospace;
  }}

  .dim-text {{
    color: var(--text-muted);
    font-size: 11.5px;
    font-family: 'IBM Plex Mono', monospace;
  }}

  .no-data {{
    text-align: center;
    padding: 48px;
    color: var(--text-muted);
    font-size: 13px;
  }}

  .sev-dot {{
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }}

  /* ── SECTION HEADER ── */
  .section-header {{
    display: flex;
    align-items: baseline;
    gap: 10px;
    margin-bottom: 16px;
  }}

  .section-title {{
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
    letter-spacing: 0.01em;
  }}

  .section-desc {{
    font-size: 12px;
    color: var(--text-muted);
  }}

  /* ── SUMMARY TAB ── */
  .summary-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    margin-top: 4px;
  }}
  .summary-block {{
    background: var(--white);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }}
  .summary-block-header {{
    background: var(--navy-900);
    padding: 14px 20px;
    border-bottom: 1px solid var(--navy-700);
  }}
  .summary-block-title {{
    font-size: 12px;
    font-weight: 700;
    color: var(--slate-300);
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }}
  .summary-block-desc {{
    font-size: 11px;
    color: var(--slate-400);
    margin-top: 3px;
  }}
  .summary-block-body {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
  }}
  .sev-stat {{
    padding: 28px 16px 24px;
    text-align: center;
    border-right: 1px solid var(--border);
    position: relative;
    cursor: pointer;
    transition: background 0.15s;
  }}
  .sev-stat:last-child {{ border-right: none; }}
  .sev-stat:hover {{ background: var(--slate-50); }}
  .sev-stat-bar {{
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
  }}
  .sev-stat-number {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 40px;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 8px;
  }}
  .sev-stat-label {{
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }}
</style>
</head>
<body>

<!-- HEADER -->
<div class="report-header">
  <div class="header-top">
    <div class="report-brand">
      <div class="brand-mark">SC</div>
      <div>
        <div class="report-title">Security &amp; Compliance Report</div>
        <div class="report-subtitle">Trivy Vulnerability &amp; License Scan</div>
      </div>
    </div>
    <div class="header-meta">
      <div class="meta-item">Source: <span>{report_path}</span></div>
      <div class="meta-item">Generated: <span>{generated_at}</span></div>
    </div>
  </div>

  <div class="metrics-bar">
    {metrics_html}
  </div>

  <div class="nav-tabs">
    <div class="nav-tab active" onclick="switchTab('overview')">Overview</div>
    <div class="nav-tab" onclick="switchTab('vuln-sum')">Vulnerability Summary</div>
    <div class="nav-tab" onclick="switchTab('vuln-detail')">All CVEs ({len(vuln_rows)})</div>
    <div class="nav-tab" onclick="switchTab('lic-sum')">License Summary</div>
    <div class="nav-tab" onclick="switchTab('lic-detail')">License Detail ({len(license_rows)})</div>
  </div>
</div>

<!-- CONTENT -->
<div class="content">

  <!-- OVERVIEW -->
  <div class="tab-panel active" id="tab-overview">
    <div class="section-header">
      <span class="section-title">Scan Overview</span>
      <span class="section-desc">Summary of vulnerability and license scan results</span>
    </div>
    <div class="summary-grid">
      <div class="summary-block">
        <div class="summary-block-header">
          <div class="summary-block-title">License Scan Results</div>
          <div class="summary-block-desc">Ket qua scan license cua ma nguon</div>
        </div>
        <div class="summary-block-body">
          <div class="sev-stat" onclick="switchTab('lic-sum');document.getElementById('lsSevFilter').value='CRITICAL';filterLS()">
            <div class="sev-stat-bar" style="background:#e53e3e"></div>
            <div class="sev-stat-number" style="color:#e53e3e">{lic_sev.get('CRITICAL',0):02d}</div>
            <div class="sev-stat-label" style="color:#e53e3e">Critical</div>
          </div>
          <div class="sev-stat" onclick="switchTab('lic-sum');document.getElementById('lsSevFilter').value='HIGH';filterLS()">
            <div class="sev-stat-bar" style="background:#dd6b20"></div>
            <div class="sev-stat-number" style="color:#dd6b20">{lic_sev.get('HIGH',0):02d}</div>
            <div class="sev-stat-label" style="color:#dd6b20">High</div>
          </div>
          <div class="sev-stat" onclick="switchTab('lic-sum');document.getElementById('lsSevFilter').value='MEDIUM';filterLS()">
            <div class="sev-stat-bar" style="background:#dd8500"></div>
            <div class="sev-stat-number" style="color:#dd8500">{lic_sev.get('MEDIUM',0):02d}</div>
            <div class="sev-stat-label" style="color:#dd8500">Medium</div>
          </div>
          <div class="sev-stat" onclick="switchTab('lic-sum');document.getElementById('lsSevFilter').value='LOW';filterLS()">
            <div class="sev-stat-bar" style="background:#2d9e5f"></div>
            <div class="sev-stat-number" style="color:#2d9e5f">{lic_sev.get('LOW',0):02d}</div>
            <div class="sev-stat-label" style="color:#2d9e5f">Low</div>
          </div>
        </div>
      </div>
      <div class="summary-block">
        <div class="summary-block-header">
          <div class="summary-block-title">Vulnerability Scan Results</div>
          <div class="summary-block-desc">Ket qua scan lo hong dependency cua ma nguon</div>
        </div>
        <div class="summary-block-body">
          <div class="sev-stat" onclick="switchTab('vuln-sum');document.getElementById('vsSevFilter').value='CRITICAL';filterVS()">
            <div class="sev-stat-bar" style="background:#e53e3e"></div>
            <div class="sev-stat-number" style="color:#e53e3e">{vuln_sev.get('CRITICAL',0):02d}</div>
            <div class="sev-stat-label" style="color:#e53e3e">Critical</div>
          </div>
          <div class="sev-stat" onclick="switchTab('vuln-sum');document.getElementById('vsSevFilter').value='HIGH';filterVS()">
            <div class="sev-stat-bar" style="background:#dd6b20"></div>
            <div class="sev-stat-number" style="color:#dd6b20">{vuln_sev.get('HIGH',0):02d}</div>
            <div class="sev-stat-label" style="color:#dd6b20">High</div>
          </div>
          <div class="sev-stat" onclick="switchTab('vuln-sum');document.getElementById('vsSevFilter').value='MEDIUM';filterVS()">
            <div class="sev-stat-bar" style="background:#dd8500"></div>
            <div class="sev-stat-number" style="color:#dd8500">{vuln_sev.get('MEDIUM',0):02d}</div>
            <div class="sev-stat-label" style="color:#dd8500">Medium</div>
          </div>
          <div class="sev-stat" onclick="switchTab('vuln-sum');document.getElementById('vsSevFilter').value='LOW';filterVS()">
            <div class="sev-stat-bar" style="background:#2d9e5f"></div>
            <div class="sev-stat-number" style="color:#2d9e5f">{vuln_sev.get('LOW',0):02d}</div>
            <div class="sev-stat-label" style="color:#2d9e5f">Low</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- VULN SUMMARY -->
  <div class="tab-panel" id="tab-vuln-sum">
    <div class="section-header">
      <span class="section-title">Affected Packages</span>
      <span class="section-desc">{len(pkg_groups)} packages — click a row to expand individual CVEs</span>
    </div>
    <div class="info-banner">
      The <strong>Fix To</strong> column shows the minimum version that resolves all CVEs for that package. Updating to this version eliminates the need to patch each CVE individually.
    </div>
    <div class="toolbar">
      <input class="search-input" type="text" id="vsSearch" placeholder="Filter by package name..." oninput="filterVS()">
      <select class="filter-select" id="vsSevFilter" onchange="filterVS()">
        <option value="">All Severities</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>UNKNOWN</option>
      </select>
      <button class="btn btn-ghost" onclick="resetVS()">Reset</button>
      <button class="btn btn-expand" onclick="toggleAll('vuln')" id="btnExpandVuln">Expand All</button>
      <div class="toolbar-right">
        <button class="btn btn-success" onclick="exportExcel()">Export Excel</button>
        <span class="row-count" id="vsCount">{len(pkg_groups)} packages</span>
      </div>
    </div>
    <div class="table-wrap">
      <div class="table-scroll">
      <table id="vsTable">
        <thead><tr>
          <th onclick="sortTable('vsTable',0)">Package <span class="si">⇅</span></th>
          <th onclick="sortTable('vsTable',1)">Current Version <span class="si">⇅</span></th>
          <th onclick="sortTable('vsTable',2)">Fix To <span class="si">⇅</span></th>
          <th onclick="sortTable('vsTable',3)">Severity <span class="si">⇅</span></th>
          <th>Breakdown</th>
          <th onclick="sortTable('vsTable',5)">CVE Count <span class="si">⇅</span></th>
          <th>Target</th>
        </tr></thead>
        <tbody id="vsBody">
          {vuln_summary_rows or '<tr><td colspan="7" class="no-data">No vulnerabilities found.</td></tr>'}
        </tbody>
      </table>
      </div>
    </div>
  </div>

  <!-- VULN DETAIL -->
  <div class="tab-panel" id="tab-vuln-detail">
    <div class="section-header">
      <span class="section-title">All CVEs</span>
      <span class="section-desc">Complete list — {len(vuln_rows)} entries across {len(pkg_groups)} packages</span>
    </div>
    <div class="toolbar">
      <input class="search-input" type="text" id="vdSearch" placeholder="Filter by package, CVE, title..." oninput="filterVD()">
      <select class="filter-select" id="vdSevFilter" onchange="filterVD()">
        <option value="">All Severities</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>UNKNOWN</option>
      </select>
      <button class="btn btn-ghost" onclick="resetVD()">Reset</button>
      <div class="toolbar-right">
        <button class="btn btn-success" onclick="exportExcel()">Export Excel</button>
        <span class="row-count" id="vdCount">{len(vuln_rows)} CVEs</span>
      </div>
    </div>
    <div class="table-wrap">
      <div class="table-scroll">
      <table id="vdTable">
        <thead><tr>
          <th onclick="sortTable('vdTable',0)">Package <span class="si">⇅</span></th>
          <th onclick="sortTable('vdTable',1)">Installed <span class="si">⇅</span></th>
          <th onclick="sortTable('vdTable',2)">Fixed In <span class="si">⇅</span></th>
          <th onclick="sortTable('vdTable',3)">CVE ID <span class="si">⇅</span></th>
          <th onclick="sortTable('vdTable',4)">Severity <span class="si">⇅</span></th>
          <th onclick="sortTable('vdTable',5)">Title <span class="si">⇅</span></th>
          <th>Target</th>
        </tr></thead>
        <tbody id="vdBody">
          {vuln_detail_rows() or '<tr><td colspan="7" class="no-data">No CVEs found.</td></tr>'}
        </tbody>
      </table>
      </div>
    </div>
  </div>

  <!-- LICENSE SUMMARY -->
  <div class="tab-panel" id="tab-lic-sum">
    <div class="section-header">
      <span class="section-title">License Summary by Package</span>
      <span class="section-desc">{len(lic_groups)} packages — click a row to expand individual licenses</span>
    </div>
    <div class="legend-bar">
      <span class="legend-label">License Type</span>
      <span class="legend-item">{lic_chip('GPL / AGPL')} Copyleft — must Replace</span>
      <span class="legend-item">{lic_chip('MPL / EPL')} Weak copyleft — Review required</span>
      <span class="legend-item">{lic_chip('MIT / BSD / ISC')} Permissive — generally OK</span>
      <span class="legend-item">{lic_chip('Apache')} Permissive — generally OK</span>
      <span class="legend-item">{lic_chip('Commercial')} Proprietary — Review required</span>
    </div>
    <div class="toolbar">
      <input class="search-input" type="text" id="lsSearch" placeholder="Filter by package, license..." oninput="filterLS()">
      <select class="filter-select" id="lsSevFilter" onchange="filterLS()">
        <option value="">All Severities</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>UNKNOWN</option>
      </select>
      <select class="filter-select" id="lsCatFilter" onchange="filterLS()">
        <option value="">All Categories</option>
        {cat_options}
      </select>
      <select class="filter-select" id="lsActionFilter" onchange="filterLS()">
        <option value="">All Actions</option>
        <option>Replace</option><option>Review</option><option>OK</option>
      </select>
      <button class="btn btn-ghost" onclick="resetLS()">Reset</button>
      <button class="btn btn-expand" onclick="toggleAll('lic')" id="btnExpandLic">Expand All</button>
      <div class="toolbar-right">
        <button class="btn btn-success" onclick="exportExcel()">Export Excel</button>
        <span class="row-count" id="lsCount">{len(lic_groups)} packages</span>
      </div>
    </div>
    <div class="table-wrap">
      <div class="table-scroll">
      <table id="lsTable">
        <thead><tr>
          <th onclick="sortTable('lsTable',0)">Package <span class="si">⇅</span></th>
          <th>Licenses</th>
          <th onclick="sortTable('lsTable',2)">Severity <span class="si">⇅</span></th>
          <th onclick="sortTable('lsTable',3)">Category <span class="si">⇅</span></th>
          <th onclick="sortTable('lsTable',4)">Action <span class="si">⇅</span></th>
          <th onclick="sortTable('lsTable',5)">Count <span class="si">⇅</span></th>
          <th>Target</th>
        </tr></thead>
        <tbody id="lsBody">
          {lic_summary_rows or '<tr><td colspan="7" class="no-data">No license issues found.</td></tr>'}
        </tbody>
      </table>
      </div>
    </div>
  </div>

  <!-- LICENSE DETAIL -->
  <div class="tab-panel" id="tab-lic-detail">
    <div class="section-header">
      <span class="section-title">License Detail</span>
      <span class="section-desc">Full list — {len(license_rows)} entries for developer compliance review</span>
    </div>
    <div class="toolbar">
      <input class="search-input" type="text" id="ldSearch" placeholder="Filter by package, license..." oninput="filterLD()">
      <select class="filter-select" id="ldSevFilter" onchange="filterLD()">
        <option value="">All Severities</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>UNKNOWN</option>
      </select>
      <select class="filter-select" id="ldCatFilter" onchange="filterLD()">
        <option value="">All Categories</option>
        {cat_options}
      </select>
      <select class="filter-select" id="ldActionFilter" onchange="filterLD()">
        <option value="">All Actions</option>
        <option>Replace</option><option>Review</option><option>OK</option>
      </select>
      <button class="btn btn-ghost" onclick="resetLD()">Reset</button>
      <div class="toolbar-right">
        <button class="btn btn-success" onclick="exportExcel()">Export Excel</button>
        <span class="row-count" id="ldCount">{len(license_rows)} licenses</span>
      </div>
    </div>
    <div class="table-wrap">
      <div class="table-scroll">
      <table id="ldTable">
        <thead><tr>
          <th onclick="sortTable('ldTable',0)">Package <span class="si">⇅</span></th>
          <th onclick="sortTable('ldTable',1)">License <span class="si">⇅</span></th>
          <th onclick="sortTable('ldTable',2)">Severity <span class="si">⇅</span></th>
          <th onclick="sortTable('ldTable',3)">Category <span class="si">⇅</span></th>
          <th onclick="sortTable('ldTable',4)">Action <span class="si">⇅</span></th>
          <th onclick="sortTable('ldTable',5)">File Path <span class="si">⇅</span></th>
          <th>Target</th>
        </tr></thead>
        <tbody id="ldBody">
          {lic_detail_rows() or '<tr><td colspan="7" class="no-data">No license issues found.</td></tr>'}
        </tbody>
      </table>
      </div>
    </div>
  </div>

</div><!-- /content -->

<script>
const PKG_GROUPS = {pkg_groups_json};
const LIC_GROUPS = {lic_groups_json};
const VULN_DATA  = {vuln_json};
const LIC_DATA   = {lic_json};
const SEV_ORDER  = {{CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4}};
const TABS       = ['overview','vuln-sum','vuln-detail','lic-sum','lic-detail'];

// ── TABS ──
function switchTab(tab) {{
  TABS.forEach(t => {{
    document.getElementById('tab-'+t).classList.toggle('active', t===tab);
  }});
  document.querySelectorAll('.nav-tab').forEach((el,i) => {{
    el.classList.toggle('active', TABS[i]===tab);
  }});
}}

// ── EXPAND / COLLAPSE ──
const expandState = {{}};
const allExpandedState = {{vuln: false, lic: false}};

function toggleDetail(type, idx) {{
  const key = type+'-'+idx;
  const rows = document.querySelectorAll('.detail-'+type+'-'+idx);
  const icon = document.getElementById('icon-'+type+'-'+idx);
  expandState[key] = !expandState[key];
  rows.forEach(r => r.style.display = expandState[key] ? 'table-row' : 'none');
  if(icon) icon.textContent = expandState[key] ? '-' : '+';
}}

function toggleAll(type) {{
  allExpandedState[type] = !allExpandedState[type];
  const expanded = allExpandedState[type];
  const data = type === 'vuln' ? PKG_GROUPS : LIC_GROUPS;
  data.forEach((g,i) => {{
    const key = type+'-'+i;
    expandState[key] = expanded;
    document.querySelectorAll('.detail-'+type+'-'+i).forEach(r => {{
      r.style.display = expanded ? 'table-row' : 'none';
    }});
    const icon = document.getElementById('icon-'+type+'-'+i);
    if(icon) icon.textContent = expanded ? '-' : '+';
  }});
  const btnId = type === 'vuln' ? 'btnExpandVuln' : 'btnExpandLic';
  document.getElementById(btnId).textContent = expanded ? 'Collapse All' : 'Expand All';
}}

// ── SORT ──
const sortState = {{}};
function sortTable(tableId, col) {{
  const tbody = document.querySelector('#'+tableId+' tbody');
  const isGrouped = ['vsTable','lsTable'].includes(tableId);
  const selClass = isGrouped
    ? (tableId==='vsTable' ? 'tr.pkg-row:not(.hidden)' : 'tr.lic-row:not(.hidden)')
    : 'tr.data-row:not(.hidden)';
  const rows = Array.from(tbody.querySelectorAll(selClass));
  const key = tableId+col;
  const asc = sortState[key] = !sortState[key];
  rows.sort((a,b) => {{
    const aCell = a.cells[col], bCell = b.cells[col];
    const aVal = aCell?.dataset.value ?? aCell?.innerText.trim() ?? '';
    const bVal = bCell?.dataset.value ?? bCell?.innerText.trim() ?? '';
    const aNum = parseFloat(aVal), bNum = parseFloat(bVal);
    if(!isNaN(aNum)&&!isNaN(bNum)) return asc?aNum-bNum:bNum-aNum;
    return asc?aVal.localeCompare(bVal):bVal.localeCompare(aVal);
  }});
  const detClass = tableId==='vsTable' ? 'detail-vuln-' : 'detail-lic-';
  rows.forEach(r => {{
    tbody.appendChild(r);
    if(isGrouped) {{
      document.querySelectorAll('.'+detClass+r.dataset.idx).forEach(sub => tbody.appendChild(sub));
    }}
  }});
  document.querySelectorAll('#'+tableId+' th .si').forEach((el,i) => {{
    el.textContent = i===col?(asc?'↑':'↓'):'⇅';
  }});
}}

// ── FILTERS ──
function filterVS() {{
  const q=document.getElementById('vsSearch').value.toLowerCase();
  const sev=document.getElementById('vsSevFilter').value;
  let c=0;
  document.querySelectorAll('#vsBody tr.pkg-row').forEach(tr=>{{
    const show=(!q||tr.innerText.toLowerCase().includes(q))&&(!sev||tr.dataset.severity===sev);
    tr.classList.toggle('hidden',!show);
    document.querySelectorAll('.detail-vuln-'+tr.dataset.idx).forEach(r=>r.classList.toggle('hidden',!show));
    if(show)c++;
  }});
  document.getElementById('vsCount').textContent=c+' packages';
}}

function filterVD() {{
  const q=document.getElementById('vdSearch').value.toLowerCase();
  const sev=document.getElementById('vdSevFilter').value;
  let c=0;
  document.querySelectorAll('#vdBody tr').forEach(tr=>{{
    const show=(!q||tr.innerText.toLowerCase().includes(q))&&(!sev||tr.dataset.severity===sev);
    tr.classList.toggle('hidden',!show);if(show)c++;
  }});
  document.getElementById('vdCount').textContent=c+' CVEs';
}}

function filterLS() {{
  const q=document.getElementById('lsSearch').value.toLowerCase();
  const sev=document.getElementById('lsSevFilter').value;
  const cat=document.getElementById('lsCatFilter').value;
  const act=document.getElementById('lsActionFilter').value;
  let c=0;
  document.querySelectorAll('#lsBody tr.lic-row').forEach(tr=>{{
    const text=tr.innerText.toLowerCase();
    const show=(!q||text.includes(q))&&(!sev||tr.dataset.severity===sev)&&(!cat||text.includes(cat.toLowerCase()))&&(!act||text.includes(act.toLowerCase()));
    tr.classList.toggle('hidden',!show);
    document.querySelectorAll('.detail-lic-'+tr.dataset.idx).forEach(r=>r.classList.toggle('hidden',!show));
    if(show)c++;
  }});
  document.getElementById('lsCount').textContent=c+' packages';
}}

function filterLD() {{
  const q=document.getElementById('ldSearch').value.toLowerCase();
  const sev=document.getElementById('ldSevFilter').value;
  const cat=document.getElementById('ldCatFilter').value;
  const act=document.getElementById('ldActionFilter').value;
  let c=0;
  document.querySelectorAll('#ldBody tr').forEach(tr=>{{
    const text=tr.innerText.toLowerCase();
    const show=(!q||text.includes(q))&&(!sev||tr.dataset.severity===sev)&&(!cat||tr.dataset.category===cat)&&(!act||text.includes(act.toLowerCase()));
    tr.classList.toggle('hidden',!show);if(show)c++;
  }});
  document.getElementById('ldCount').textContent=c+' licenses';
}}

function resetVS(){{document.getElementById('vsSearch').value='';document.getElementById('vsSevFilter').value='';filterVS();}}
function resetVD(){{document.getElementById('vdSearch').value='';document.getElementById('vdSevFilter').value='';filterVD();}}
function resetLS(){{document.getElementById('lsSearch').value='';document.getElementById('lsSevFilter').value='';document.getElementById('lsCatFilter').value='';document.getElementById('lsActionFilter').value='';filterLS();}}
function resetLD(){{document.getElementById('ldSearch').value='';document.getElementById('ldSevFilter').value='';document.getElementById('ldCatFilter').value='';document.getElementById('ldActionFilter').value='';filterLD();}}

// ── EXPORT EXCEL ──
function colRef(c) {{
  // Convert 0-based column index to Excel letter (A, B, ... Z, AA, ...)
  let s=''; c++;
  while(c>0){{ s=String.fromCharCode(65+(c-1)%26)+s; c=Math.floor((c-1)/26); }}
  return s;
}}

const SEV=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'];
const SEVERITY_STYLES = {{
  CRITICAL: {{ fill: '8B0000', font: 'FFFFFF' }},
  HIGH:     {{ fill: 'FF0000', font: 'FFFFFF' }},
  MEDIUM:   {{ fill: 'FFD966', font: '000000' }},
  LOW:      {{ fill: '92D050', font: '000000' }}
}};

function sevRank(severity) {{
  const idx = SEV.indexOf(severity);
  return idx === -1 ? 99 : idx;
}}

function applyMergesAndStyle(ws, merges, headerRow, totalCols) {{
  ws['!merges'] = merges;
  // Header style: navy bg, white bold text
  for(let c=0;c<totalCols;c++) {{
    const ref = colRef(c)+'1';
    if(!ws[ref]) continue;
    ws[ref].s = {{
      fill:{{ fgColor:{{ rgb:'0D1629' }} }},
      font:{{ bold:true, color:{{ rgb:'B8CCE0' }}, sz:10 }},
      alignment:{{ vertical:'center', horizontal:'center', wrapText:true }},
      border:{{ bottom:{{ style:'thin', color:{{ rgb:'234B7A' }} }} }}
    }};
  }}
  // Data rows: alternating, with merge cells vertically centered
  const range = XLSX.utils.decode_range(ws['!ref']);
  for(let r=1; r<=range.e.r; r++) {{
    const isAlt = r%2===0;
    for(let c=0;c<totalCols;c++) {{
      const ref = colRef(c)+(r+1);
      if(!ws[ref]) ws[ref]={{t:'s',v:''}};
      ws[ref].s = {{
        fill:{{ fgColor:{{ rgb: isAlt ? 'F5F8FC' : 'FFFFFF' }} }},
        font:{{ sz:10 }},
        alignment:{{ vertical:'center', wrapText:false }},
        border:{{
          bottom:{{ style:'thin', color:{{ rgb:'DDE8F2' }} }},
          right:{{ style:'thin', color:{{ rgb:'DDE8F2' }} }}
        }}
      }};
    }}
  }}
  ws['!sheetView'] = [{{ state:'frozen', ySplit:1 }}];
}}

function applySeverityColors(ws, severityCol) {{
  if(!ws['!ref']) return;
  const range = XLSX.utils.decode_range(ws['!ref']);
  for(let r=1; r<=range.e.r; r++) {{
    const ref = colRef(severityCol)+(r+1);
    const cell = ws[ref];
    if(!cell) continue;
    const style = SEVERITY_STYLES[String(cell.v || '').toUpperCase()];
    if(!style) continue;
    const current = cell.s || {{}};
    cell.s = Object.assign({{}}, current, {{
      fill:{{ patternType:'solid', fgColor:{{ rgb:style.fill }} }},
      font:Object.assign({{}}, current.font || {{}}, {{ bold:true, color:{{ rgb:style.font }} }}),
      alignment:Object.assign({{}}, current.alignment || {{}}, {{ horizontal:'center', vertical:'center' }})
    }});
  }}
}}

function buildVulnSheet() {{
  // Grouped by package, sorted by highest severity inside each group
  const rows=[['Package','Vulnerability ID','Severity','Installed Version','Fixed Version']];
  const merges=[];
  let rowIdx=1; // 0-based, after header

  PKG_GROUPS.forEach(g=>{{
    const cves=[...g.cves].sort((a,b)=>sevRank(a.severity)-sevRank(b.severity));
    const start=rowIdx;
    cves.forEach((cv,i)=>{{
      rows.push([
        i===0 ? g.pkg : '',   // Package: only first row of group
        cv.cve,
        cv.severity,
        g.version,
        cv.fixed || '-'
      ]);
      rowIdx++;
    }});
    const end=rowIdx-1;
    if(end>start) {{
      // Merge Package col (col 0) and Installed Version col (col 3) for the group
      merges.push({{s:{{r:start,c:0}},e:{{r:end,c:0}}}});
      merges.push({{s:{{r:start,c:3}},e:{{r:end,c:3}}}});
    }}
  }});

  const ws=XLSX.utils.aoa_to_sheet(rows);
  ws['!cols']=[40,22,10,16,28].map(w=>{{return{{wch:w}}}});
  applyMergesAndStyle(ws, merges, rows[0], 5);
  applySeverityColors(ws, 2);
  return ws;
}}

function buildLicSheet() {{
  const rows=[['Package','License','Severity','File Path']];
  const merges=[];
  let rowIdx=1;

  LIC_GROUPS.forEach(g=>{{
    const lics=[...g.lics].sort((a,b)=>sevRank(a.severity)-sevRank(b.severity));
    const start=rowIdx;
    lics.forEach((lc,i)=>{{
      rows.push([
        i===0 ? g.pkg : '',
        lc.license,
        lc.severity,
        lc.filepath || g.target
      ]);
      rowIdx++;
    }});
    const end=rowIdx-1;
    if(end>start) {{
      merges.push({{s:{{r:start,c:0}},e:{{r:end,c:0}}}});
    }}
  }});

  const ws=XLSX.utils.aoa_to_sheet(rows);
  ws['!cols']=[40,30,10,40].map(w=>{{return{{wch:w}}}});
  applyMergesAndStyle(ws, merges, rows[0], 4);
  applySeverityColors(ws, 2);
  return ws;
}}

function buildRemediationSheet() {{
  const rows=[['#','Package','Current Version','Fix To','Highest Severity','CVE Count','Status','Assigned To','Notes']];
  PKG_GROUPS.forEach((g,i)=>rows.push([i+1,g.pkg,g.version,g.fix_to,g.highest_severity,g.cve_count,'Pending','','']));
  const ws=XLSX.utils.aoa_to_sheet(rows);
  ws['!cols']=[4,40,14,14,14,10,10,15,30].map(w=>{{return{{wch:w}}}});
  applyMergesAndStyle(ws,[],rows[0],9);
  applySeverityColors(ws, 4);
  return ws;
}}

function buildComplianceSheet() {{
  const rows=[['#','Package','Licenses','Highest Severity','Recommended Action','Decision','Approved By','Notes']];
  LIC_GROUPS.forEach((g,i)=>rows.push([i+1,g.pkg,g.license_names.join(', '),g.highest_severity,g.action,'','','']));
  const ws=XLSX.utils.aoa_to_sheet(rows);
  ws['!cols']=[4,40,45,12,16,12,15,30].map(w=>{{return{{wch:w}}}});
  applyMergesAndStyle(ws,[],rows[0],8);
  applySeverityColors(ws, 3);
  return ws;
}}

function buildOverviewSheet() {{
  const SEV_COLORS = {{CRITICAL:'E53E3E',HIGH:'DD6B20',MEDIUM:'DD8500',LOW:'2D9E5F',UNKNOWN:'718096'}};
  const licSev={{}}, vulnSev={{}};
  LIC_DATA.forEach(r=>licSev[r.severity]=(licSev[r.severity]||0)+1);
  VULN_DATA.forEach(r=>vulnSev[r.severity]=(vulnSev[r.severity]||0)+1);

  const rows=[
    ['Scan Type','CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN','Total'],
    ['License Scan',licSev.CRITICAL||0,licSev.HIGH||0,licSev.MEDIUM||0,licSev.LOW||0,licSev.UNKNOWN||0,LIC_DATA.length],
    ['Vulnerability Scan',vulnSev.CRITICAL||0,vulnSev.HIGH||0,vulnSev.MEDIUM||0,vulnSev.LOW||0,vulnSev.UNKNOWN||0,VULN_DATA.length],
  ];
  const ws=XLSX.utils.aoa_to_sheet(rows);
  ws['!cols']=[22,10,10,10,10,10,10].map(w=>{{return{{wch:w}}}});

  // Style header row
  ['A1','B1','C1','D1','E1','F1','G1'].forEach(ref=>{{
    if(!ws[ref])return;
    ws[ref].s={{fill:{{fgColor:{{rgb:'0D1629'}}}},font:{{bold:true,color:{{rgb:'B8CCE0'}},sz:11}},alignment:{{horizontal:'center',vertical:'center'}}}};
  }});
  // Style severity headers with their colors
  const sevCols={{B1:'E53E3E',C1:'DD6B20',D1:'DD8500',E1:'2D9E5F',F1:'718096'}};
  Object.entries(sevCols).forEach(([ref,color])=>{{
    if(!ws[ref])return;
    ws[ref].s={{fill:{{fgColor:{{rgb:'0D1629'}}}},font:{{bold:true,color:{{rgb:color}},sz:11}},alignment:{{horizontal:'center',vertical:'center'}}}};
  }});
  // Style data rows
  [2,3].forEach(r=>{{
    ['A','B','C','D','E','F','G'].forEach(c=>{{
      const ref=c+r;
      if(!ws[ref])ws[ref]={{t:'n',v:0}};
      ws[ref].s={{
        fill:{{fgColor:{{rgb:r===2?'F5F8FC':'FFFFFF'}}}},
        font:{{sz:11,bold:c==='A'||c==='G'}},
        alignment:{{horizontal:c==='A'?'left':'center',vertical:'center'}},
        border:{{bottom:{{style:'thin',color:{{rgb:'DDE8F2'}}}},right:{{style:'thin',color:{{rgb:'DDE8F2'}}}}}}
      }};
    }});
  }});
  ws['!sheetView']=[{{state:'frozen',ySplit:1}}];
  return ws;
}}

function exportExcel() {{
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, buildOverviewSheet(), 'Overview');
  XLSX.utils.book_append_sheet(wb, buildVulnSheet(), 'Vulnerability');
  XLSX.utils.book_append_sheet(wb, buildLicSheet(),  'License');
  XLSX.writeFile(wb, 'trivy-report.xlsx');
}}
</script>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    print(f"Report saved: {output_path}")
    print(f"  Vulnerability packages : {len(pkg_groups)}")
    print(f"  Total CVEs             : {len(vuln_rows)}")
    print(f"  License packages       : {len(lic_groups)}")
    print(f"  Total licenses         : {len(license_rows)}")

if __name__ == "__main__":
    report = sys.argv[1] if len(sys.argv) > 1 else "report.json"
    output = sys.argv[2] if len(sys.argv) > 2 else "report.html"
    generate_html(report, output)
