"""
autoscan.license_rules - Normalize SBOM license names to SPDX IDs and clean hashes.
Usage: python -m autoscan.license_rules <input.json>
Outputs: <input>-fix.json + license-log-<timestamp>.txt

Handles CycloneDX SBOM license shapes:
  - {"license": {"id": "MIT"}}                  (already SPDX, kept)
  - {"license": {"name": "Apache License 2.0"}} (normalized -> id)
  - {"license": {"name": "...", "url": "..."}}  (url used as fallback)
  - {"expression": "MIT OR Apache-2.0"}          (kept as-is)
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Exact + alias SPDX map (lowercased keys for case-insensitive match)
SPDX_EXACT = {
    # MIT
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "the mit license (mit)": "MIT",
    # Apache
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0",
    "the apache software license, version 2.0": "Apache-2.0",
    "apache software license - version 2.0": "Apache-2.0",
    "apache public license 2.0": "Apache-2.0",
    # BSD
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "the bsd 3-clause license": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "the bsd 2-clause license": "BSD-2-Clause",
    "new bsd license": "BSD-3-Clause",
    "revised bsd": "BSD-3-Clause",
    # EPL / Eclipse
    "epl-1.0": "EPL-1.0",
    "eclipse public license 1.0": "EPL-1.0",
    "eclipse public license - v 1.0": "EPL-1.0",
    "eclipse public license v1.0": "EPL-1.0",
    "epl-2.0": "EPL-2.0",
    "eclipse public license 2.0": "EPL-2.0",
    "eclipse public license - v 2.0": "EPL-2.0",
    "eclipse public license v2.0": "EPL-2.0",
    # EDL
    "eclipse distribution license - v 1.0": "BSD-3-Clause",
    "eclipse distribution license (new bsd license)": "BSD-3-Clause",
    # LGPL
    "lgpl": "LGPL-2.1-or-later",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl 2.1": "LGPL-2.1-only",
    "lgpl-2.1-or-later": "LGPL-2.1-or-later",
    "gnu lesser general public license": "LGPL-2.1-or-later",
    "gnu lesser general public license (lgpl), version 2.1": "LGPL-2.1-or-later",
    "gnu lesser general public license, version 2.1": "LGPL-2.1-only",
    "gnu lesser general public license version 2.1": "LGPL-2.1-only",
    "gnu lesser general public license 3.0": "LGPL-3.0-only",
    "gnu lesser general public license v3.0": "LGPL-3.0-only",
    "gnu lesser public license": "LGPL-3.0-only",
    "gnu lesser general public licence": "LGPL-3.0-only",
    # GPL
    "gpl": "GPL-3.0-or-later",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gnu general public license": "GPL-3.0-or-later",
    "gnu general public license, version 2": "GPL-2.0-only",
    "gnu general public license v2.0": "GPL-2.0-only",
    "gnu general public license, version 2 (gpl2), with the classpath exception": "GPL-2.0-with-classpath-exception",
    "gpl2 w/ cpe": "GPL-2.0-with-classpath-exception",
    # AGPL
    "agpl-3.0": "AGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only",
    # MPL
    "mpl 1.1": "MPL-1.1",
    "mpl-1.1": "MPL-1.1",
    "mpl 2.0": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 1.1": "MPL-1.1",
    "mozilla public license 2.0": "MPL-2.0",
    "mozilla public license, version 2.0": "MPL-2.0",
    # CDDL
    "cddl": "CDDL-1.0",
    "cddl-1.0": "CDDL-1.0",
    "cddl 1.1": "CDDL-1.1",
    "common development and distribution license": "CDDL-1.0",
    "common development and distribution license (cddl) v1.0": "CDDL-1.0",
    "common development and distribution license 1.0": "CDDL-1.0",
    # CPL
    "cpl": "CPL-1.0",
    "cpl-1.0": "CPL-1.0",
    "common public license version 1.0": "CPL-1.0",
    # ISC / others
    "isc": "ISC",
    "isc license": "ISC",
    "zlib": "Zlib",
    "wtfpl": "WTFPL",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "cc0-1.0": "CC0-1.0",
    "cc0 1.0 universal": "CC0-1.0",
    "public domain": "LicenseRef-Public-Domain",
    "python software foundation license": "PSF-2.0",
    "go license": "BSD-3-Clause",
    # Vendor-specific licenses commonly seen in Java/npm deps
    "bouncy castle licence": "MIT",
    "bouncy castle license": "MIT",
    "the bouncy castle license": "MIT",
    "json license": "JSON",
    "the json license": "JSON",
    "json": "JSON",
    "indiana university extreme! lab software license": "BSD-3-Clause",
    "provided without support or warranty": "LicenseRef-Public-Domain",
    "android software development kit license": "LicenseRef-Android-SDK",
    "google api terms of service": "LicenseRef-Google-API-TOS",
    "creative commons": "LicenseRef-CC",
    "creative commons attribution 4.0": "CC-BY-4.0",
    "creative commons zero": "CC0-1.0",
    "do what the f*ck you want to public license": "WTFPL",
    "0bsd": "0BSD",
    "blueoak-1.0.0": "BlueOak-1.0.0",
    "python-2.0": "Python-2.0",
    "psf-2.0": "PSF-2.0",
    "the gnu general public license, v2 with universal foss exception, v1.0": "LicenseRef-GPLv2-Universal-FOSS-Exception",
    "universal permissive license": "UPL-1.0",
    "universal permissive license, version 1.0": "UPL-1.0",
    "upl-1.0": "UPL-1.0",
    "the universal permissive license (upl), version 1.0": "UPL-1.0",
}

# Regex patterns for fuzzy matching (checked after exact)
SPDX_PATTERNS = [
    (re.compile(r"apache.*2", re.I), "Apache-2.0"),
    (re.compile(r"\bmit\b", re.I), "MIT"),
    (re.compile(r"bsd.*3", re.I), "BSD-3-Clause"),
    (re.compile(r"bsd.*2", re.I), "BSD-2-Clause"),
    (re.compile(r"\bbsd\b", re.I), "BSD-3-Clause"),
    (re.compile(r"eclipse public.*2", re.I), "EPL-2.0"),
    (re.compile(r"eclipse public.*1", re.I), "EPL-1.0"),
    (re.compile(r"eclipse distribution", re.I), "BSD-3-Clause"),
    (re.compile(r"lesser general public.*3", re.I), "LGPL-3.0-only"),
    (re.compile(r"lesser general public.*2\.1", re.I), "LGPL-2.1-or-later"),
    (re.compile(r"lesser general public", re.I), "LGPL-2.1-or-later"),
    (re.compile(r"affero", re.I), "AGPL-3.0-only"),
    (re.compile(r"general public.*2", re.I), "GPL-2.0-only"),
    (re.compile(r"general public.*3", re.I), "GPL-3.0-only"),
    (re.compile(r"general public", re.I), "GPL-3.0-or-later"),
    (re.compile(r"mozilla public.*2", re.I), "MPL-2.0"),
    (re.compile(r"mozilla public.*1", re.I), "MPL-1.1"),
    (re.compile(r"common development and distribution", re.I), "CDDL-1.0"),
    (re.compile(r"common public license", re.I), "CPL-1.0"),
    (re.compile(r"\bisc\b", re.I), "ISC"),
    (re.compile(r"public domain", re.I), "LicenseRef-Public-Domain"),
    (re.compile(r"bouncy castle", re.I), "MIT"),
    (re.compile(r"\bjson license\b", re.I), "JSON"),
    (re.compile(r"universal permissive", re.I), "UPL-1.0"),
    (re.compile(r"creative commons.*zero", re.I), "CC0-1.0"),
    (re.compile(r"creative commons.*attribution.*4", re.I), "CC-BY-4.0"),
]

# URL to SPDX fallback
URL_PATTERNS = [
    (re.compile(r"apache\.org/licenses/license-2", re.I), "Apache-2.0"),
    (re.compile(r"opensource\.org/licenses/mit", re.I), "MIT"),
    (re.compile(r"opensource\.org/licenses/bsd-3", re.I), "BSD-3-Clause"),
    (re.compile(r"opensource\.org/licenses/bsd-2", re.I), "BSD-2-Clause"),
    (re.compile(r"eclipse\.org/legal/epl-2", re.I), "EPL-2.0"),
    (re.compile(r"eclipse\.org/legal/epl-v?1", re.I), "EPL-1.0"),
    (re.compile(r"eclipse\.org/org/documents/edl", re.I), "BSD-3-Clause"),
    (re.compile(r"gnu\.org/licenses/lgpl-3", re.I), "LGPL-3.0-only"),
    (re.compile(r"gnu\.org/licenses/lgpl", re.I), "LGPL-2.1-or-later"),
    (re.compile(r"gnu\.org/licenses/agpl", re.I), "AGPL-3.0-only"),
    (re.compile(r"gnu\.org/licenses/gpl-3", re.I), "GPL-3.0-only"),
    (re.compile(r"gnu\.org/licenses/gpl", re.I), "GPL-2.0-only"),
    (re.compile(r"mozilla\.org/.*mpl/2", re.I), "MPL-2.0"),
]

# Common valid SPDX IDs - if id already one of these, keep untouched
KNOWN_SPDX_IDS = set(SPDX_EXACT.values()) | {
    "Apache-2.0", "MIT", "BSD-3-Clause", "BSD-2-Clause", "ISC", "Zlib",
    "EPL-1.0", "EPL-2.0", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only",
    "GPL-2.0-only", "GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0-only",
    "MPL-1.1", "MPL-2.0", "CDDL-1.0", "CDDL-1.1", "CPL-1.0",
    "GPL-2.0-with-classpath-exception", "CC0-1.0", "Unlicense", "WTFPL", "PSF-2.0",
}


def normalize_license_name(name: str) -> str:
    if not name:
        return ""
    key = name.strip().lower()
    # 1. exact / alias
    if key in SPDX_EXACT:
        return SPDX_EXACT[key]
    # 2. fuzzy pattern
    for pat, spdx in SPDX_PATTERNS:
        if pat.search(name):
            return spdx
    # 3. fallback LicenseRef
    normalized = re.sub(r'[^a-zA-Z0-9]+', '-', name.strip()).strip('-')
    return f"LicenseRef-{normalized}"


def normalize_from_url(url: str) -> str:
    if not url:
        return ""
    for pat, spdx in URL_PATTERNS:
        if pat.search(url):
            return spdx
    return ""


def process_license_entry(lic, log_lines, timestamp, stats):
    """
    lic is one element of component['licenses'].
    Possible shapes:
      {"license": {"id": "..."}}
      {"license": {"name": "..."}}
      {"license": {"name": "...", "url": "..."}}
      {"expression": "MIT OR Apache-2.0"}
    """
    # CycloneDX expression form - leave as-is
    if "expression" in lic:
        stats["expression"] += 1
        return

    lic_obj = lic.get("license")
    if not isinstance(lic_obj, dict):
        stats["malformed"] += 1
        return

    existing_id = lic_obj.get("id")
    name = lic_obj.get("name")
    url = ""
    # url can be a string or dict {"url": ...}
    raw_url = lic_obj.get("url")
    if isinstance(raw_url, str):
        url = raw_url

    # Case 1: already has valid SPDX id
    if existing_id:
        if existing_id in KNOWN_SPDX_IDS or existing_id.startswith("LicenseRef-"):
            stats["already_id"] += 1
            return
        # id present but not standard -> try normalize
        new_id = normalize_license_name(existing_id)
        lic_obj["id"] = new_id
        stats["fixed_id"] += 1
        log_lines.append(f"[{timestamp}] id '{existing_id}' -> '{new_id}'")
        return

    # Case 2: name present -> normalize
    if name:
        new_id = normalize_license_name(name)
        lic_obj["id"] = new_id
        lic_obj.pop("name", None)
        stats["from_name"] += 1
        log_lines.append(f"[{timestamp}] name '{name}' -> id '{new_id}'")
        return

    # Case 3: only url present -> derive
    if url:
        new_id = normalize_from_url(url)
        if new_id:
            lic_obj["id"] = new_id
            stats["from_url"] += 1
            log_lines.append(f"[{timestamp}] url '{url}' -> id '{new_id}'")
        else:
            lic_obj["id"] = "LicenseRef-Unknown"
            stats["unknown"] += 1
            log_lines.append(f"[{timestamp}] url '{url}' -> id 'LicenseRef-Unknown' (no match)")
        return

    stats["empty"] += 1


def update_licenses_and_hashes_in_bom(data, log_file_path):
    log_lines = []
    timestamp = datetime.now(timezone.utc).isoformat()
    stats = {
        "components": 0, "components_with_licenses": 0,
        "already_id": 0, "fixed_id": 0, "from_name": 0,
        "from_url": 0, "expression": 0, "unknown": 0,
        "empty": 0, "malformed": 0, "hashes_filtered": 0,
    }

    for component in data.get("components", []):
        stats["components"] += 1

        if "licenses" in component and component["licenses"]:
            stats["components_with_licenses"] += 1
            for lic in component["licenses"]:
                process_license_entry(lic, log_lines, timestamp, stats)

        if "hashes" in component:
            before = len(component["hashes"])
            component["hashes"] = [
                h for h in component["hashes"]
                if h.get("alg") in ("SHA-256", "SHA-1", "MD5")
            ]
            stats["hashes_filtered"] += before - len(component["hashes"])

    # Summary header
    summary = [
        f"[{timestamp}] License normalization log -> {log_file_path}",
        f"[{timestamp}] Components total          : {stats['components']}",
        f"[{timestamp}] Components with licenses  : {stats['components_with_licenses']}",
        f"[{timestamp}] Already valid SPDX id     : {stats['already_id']}",
        f"[{timestamp}] Fixed non-standard id     : {stats['fixed_id']}",
        f"[{timestamp}] Normalized from name      : {stats['from_name']}",
        f"[{timestamp}] Derived from url          : {stats['from_url']}",
        f"[{timestamp}] CycloneDX expression kept : {stats['expression']}",
        f"[{timestamp}] Unknown (LicenseRef)      : {stats['unknown']}",
        f"[{timestamp}] Empty license entries     : {stats['empty']}",
        f"[{timestamp}] Malformed entries         : {stats['malformed']}",
        f"[{timestamp}] Hashes filtered out       : {stats['hashes_filtered']}",
        "-" * 60,
    ]

    if stats["components_with_licenses"] == 0:
        summary.append(f"[{timestamp}] WARNING: No components with 'licenses' field found in SBOM.")

    with open(log_file_path, "w", encoding="utf-8") as log_file:
        log_file.write("\n".join(summary + log_lines))

    return data, stats


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m autoscan.license_rules <input.json>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    if not input_file.is_file():
        print(f"File not found: {input_file}")
        sys.exit(1)

    output_file = input_file.with_name(input_file.stem + "-fix.json")
    safe_timestamp = datetime.now(timezone.utc).isoformat().split(".")[0].replace(":", "-")
    log_file = input_file.parent / f"license-log-{safe_timestamp}.txt"

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            bom_data = json.load(f)
    except Exception as e:
        print(f"Read error: {e}")
        sys.exit(1)

    updated_bom, stats = update_licenses_and_hashes_in_bom(bom_data, str(log_file))

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(updated_bom, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Write error: {e}")
        sys.exit(1)

    total_fixed = stats["fixed_id"] + stats["from_name"] + stats["from_url"]
    print(f"OK -> {output_file}  ({total_fixed} normalized, "
          f"{stats['already_id']} kept, {stats['unknown']} unknown)")


if __name__ == "__main__":
    main()
