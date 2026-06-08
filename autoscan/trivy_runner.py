from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .license_inventory import augment_report_with_sbom_licenses
from .models import CommandRecord
from .utils import count_trivy_findings, load_json, run_command, tool_exists, write_json


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


def _vuln_only_report(data: dict[str, Any]) -> dict[str, Any]:
    copied = deepcopy(data)
    for result in copied.get("Results") or []:
        if isinstance(result, dict):
            result.pop("Licenses", None)
    return copied


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
    headers = ["Target", "Package", "License", "Severity", "Category", "FilePath"]
    rows = _license_rows(data)
    with output_path.open("w", encoding="utf-8") as fh:
        fh.write("\t".join(headers) + "\n")
        for row in rows:
            values = [
                row.get("Target") or "-",
                row.get("PkgName") or row.get("Package") or "-",
                row.get("Name") or "-",
                row.get("Severity") or "-",
                row.get("Category") or "-",
                row.get("FilePath") or "-",
            ]
            fh.write("\t".join(str(value).replace("\t", " ") for value in values) + "\n")


def _derive_split_outputs(outputs: dict[str, Path]) -> None:
    data = load_json(outputs["report_json"])
    write_json(outputs["license_json"], _license_only_report(data))
    write_json(outputs["vuln_json"], _vuln_only_report(data))
    _write_license_table(_license_only_report(data), outputs["license_txt"])


def scan_sbom(sbom_path: Path, output_dir: Path, log_file: Path) -> tuple[dict[str, Path], int, int, list[CommandRecord]]:
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
    _derive_split_outputs(outputs)
    if log_file:
        with log_file.open("a", encoding="utf-8") as fh:
            fh.write(
                "\n[license-inventory]\n"
                f"Added {added_to_report} SBOM license rows to report.json\n"
                "Derived license.json, vuln.json, and license.txt from report.json for faster scans\n"
            )

    vuln_count, license_count = count_trivy_findings(outputs["report_json"])
    return outputs, vuln_count, license_count, records
