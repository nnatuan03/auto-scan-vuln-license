from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .license_inventory import augment_report_with_sbom_licenses
from .license_policy import classify_license_ref, is_manifest_package_name, package_license_override
from .models import CommandRecord
from .package_names import annotate_report_package_names, canonical_pkg_key
from .utils import load_json, run_command, tool_exists, write_json


class TrivyScanError(RuntimeError):
    pass


def _run_trivy(command: list[str], cwd: Path, log_file: Path, output_file: Path) -> CommandRecord:
    record, _, _ = run_command(command, cwd=cwd, log_file=log_file)
    if record.returncode != 0 or not output_file.is_file():
        raise TrivyScanError(f"Trivy command failed: {' '.join(command)}")
    return record


def _license_only_report(data: dict[str, Any]) -> dict[str, Any]:
    copied = deepcopy(data)
    for result in copied.get("Results") or []:
        if isinstance(result, dict):
            result.pop("Vulnerabilities", None)
    return copied


def _append_unique(values: list[str], value: object, *, keep_dash: bool = False) -> None:
    text = str(value or "").strip()
    if not text:
        return
    if text == "-" and not keep_dash:
        return
    if text not in values:
        values.append(text)


def _dedupe_license_report(data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, int]]:
    copied = _license_only_report(data)
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    raw_count = 0

    for result in copied.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target") or "-"
        for item in result.get("Licenses") or []:
            if not isinstance(item, dict):
                continue
            raw_count += 1
            package = str(item.get("PkgName") or item.get("Package") or "").strip()
            if is_manifest_package_name(package):
                continue
            license_name = str(item.get("Name") or "").strip()
            override = package_license_override(package)
            if override and (not license_name or license_name == "LicenseRef-No-Declared-License" or license_name.startswith("LicenseRef-Unknown")):
                license_name = override
            severity = str(item.get("Severity") or "UNKNOWN").strip() or "UNKNOWN"
            ref_classification = classify_license_ref(license_name)
            if ref_classification:
                severity = ref_classification[0]
            key = (canonical_pkg_key(package) or package, license_name, severity)
            grouped_item = grouped.setdefault(key, {
                **item,
                "PkgName": package,
                "Name": license_name,
                "Severity": severity,
                "Target": target,
                "_AutoScanTargets": [],
                "_AutoScanFilePaths": [],
                "_AutoScanOccurrences": 0,
            })
            grouped_item.pop("Category", None)
            grouped_item["_AutoScanOccurrences"] += 1
            _append_unique(grouped_item["_AutoScanTargets"], target, keep_dash=True)
            _append_unique(grouped_item["_AutoScanFilePaths"], item.get("FilePath"))

    deduped = sorted(
        grouped.values(),
        key=lambda row: (
            canonical_pkg_key(row.get("PkgName") or row.get("Package") or ""),
            str(row.get("Name") or "").lower(),
            str(row.get("Severity") or "UNKNOWN"),
        ),
    )
    for item in deduped:
        targets = item.get("_AutoScanTargets") or []
        filepaths = item.get("_AutoScanFilePaths") or []
        item["Target"] = "\n".join(targets) if targets else item.get("Target", "-")
        item["FilePath"] = "\n".join(filepaths) if filepaths else item.get("FilePath", "-")

    metadata = copied.setdefault("Metadata", {})
    if isinstance(metadata, dict):
        autoscan = metadata.setdefault("AutoScan", {})
        if isinstance(autoscan, dict):
            autoscan["license_deduplication"] = {
                "raw": raw_count,
                "unique": len(deduped),
                "duplicates_removed": max(raw_count - len(deduped), 0),
            }

    copied["Results"] = []
    if deduped:
        copied["Results"].append({
            "Target": "AutoScan License Findings",
            "Class": "autoscan-license-deduped",
            "Type": "autoscan",
            "Licenses": deduped,
        })
    return copied, {
        "raw": raw_count,
        "unique": len(deduped),
        "duplicates_removed": max(raw_count - len(deduped), 0),
    }


def _vuln_only_report(data: dict[str, Any]) -> dict[str, Any]:
    copied = deepcopy(data)
    for result in copied.get("Results") or []:
        if isinstance(result, dict):
            result.pop("Licenses", None)
    return copied


def _unique_vulnerability_count(data: dict[str, Any]) -> int:
    seen: set[tuple[str, str, str, str, str]] = set()
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            package = str(item.get("PkgName") or item.get("Package") or "").strip()
            vuln_id = str(item.get("VulnerabilityID") or item.get("Title") or "").strip()
            installed = str(item.get("InstalledVersion") or "").strip()
            fixed = str(item.get("FixedVersion") or "").strip()
            severity = str(item.get("Severity") or "UNKNOWN").strip() or "UNKNOWN"
            seen.add((canonical_pkg_key(package) or package, vuln_id, installed, fixed, severity))
    return len(seen)


def _license_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target") or "-"
        for item in result.get("Licenses") or []:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            row.setdefault("Target", target)
            rows.append(row)
    return rows


def _write_license_table(data: dict[str, Any], output_path: Path) -> None:
    headers = ["Target", "Package", "License", "Severity", "FilePath"]
    rows = _license_rows(data)
    with output_path.open("w", encoding="utf-8") as fh:
        fh.write("\t".join(headers) + "\n")
        for row in rows:
            values = [
                row.get("Target") or "-",
                row.get("PkgName") or row.get("Package") or "-",
                row.get("Name") or "-",
                row.get("Severity") or "-",
                row.get("FilePath") or "-",
            ]
            fh.write("\t".join(str(value).replace("\t", " ") for value in values) + "\n")


def _derive_split_outputs(outputs: dict[str, Path]) -> dict[str, int]:
    data = load_json(outputs["report_json"])
    license_report, license_dedup_stats = _dedupe_license_report(data)
    write_json(outputs["license_json"], license_report)
    write_json(outputs["vuln_json"], _vuln_only_report(data))
    _write_license_table(license_report, outputs["license_txt"])
    return license_dedup_stats


def scan_sbom(sbom_path: Path, output_dir: Path, log_file: Path) -> tuple[dict[str, Path], int, int, list[CommandRecord], dict[str, Any]]:
    if not tool_exists("trivy"):
        raise TrivyScanError("trivy not found in PATH")

    records: list[CommandRecord] = []
    outputs = {
        "report_json": output_dir / "report.json",
        "license_json": output_dir / "license.json",
        "license_txt": output_dir / "license.txt",
        "vuln_json": output_dir / "vuln.json",
    }

    records.append(_run_trivy([
        "trivy", "sbom", "--scanners", "vuln,license", "--format", "json",
        "--output", str(outputs["report_json"]), str(sbom_path)
    ], output_dir, log_file, outputs["report_json"]))

    added_to_report = augment_report_with_sbom_licenses(outputs["report_json"], sbom_path)
    report_data = load_json(outputs["report_json"])
    package_name_stats = annotate_report_package_names(report_data)
    write_json(outputs["report_json"], report_data)
    license_dedup_stats = _derive_split_outputs(outputs)
    if log_file:
        with log_file.open("a", encoding="utf-8") as fh:
            fh.write(
                "\n[license-inventory]\n"
                f"Added {added_to_report} SBOM license rows to report.json\n"
                f"License findings raw: {license_dedup_stats['raw']}, "
                f"unique: {license_dedup_stats['unique']}, "
                f"duplicates removed in license.json/license.txt: {license_dedup_stats['duplicates_removed']}\n"
                "\n[package-name-resolution]\n"
                f"Vulnerabilities raw missing: {package_name_stats['vulnerabilities']['raw_missing']}, "
                f"resolved: {package_name_stats['vulnerabilities']['resolved_from_fallback']}, "
                f"unresolved: {package_name_stats['vulnerabilities']['unresolved']}\n"
                f"Licenses raw missing: {package_name_stats['licenses']['raw_missing']}, "
                f"resolved: {package_name_stats['licenses']['resolved_from_fallback']}, "
                f"unresolved: {package_name_stats['licenses']['unresolved']}\n"
                "Derived license.json, vuln.json, and license.txt from report.json for faster scans\n"
            )

    vuln_count = _unique_vulnerability_count(report_data)
    license_count = license_dedup_stats["unique"]
    return outputs, vuln_count, license_count, records, package_name_stats
