from __future__ import annotations

from pathlib import Path

from .license_inventory import augment_report_with_sbom_licenses
from .models import CommandRecord
from .utils import count_trivy_findings, run_command, tool_exists


class TrivyScanError(RuntimeError):
    pass


def _run_trivy(command: list[str], cwd: Path, log_file: Path, output_file: Path) -> CommandRecord:
    record, _, _ = run_command(command, cwd=cwd, log_file=log_file)
    if record.returncode != 0 or not output_file.is_file():
        raise TrivyScanError(f"Trivy command failed: {' '.join(command)}")
    return record


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

    records.append(_run_trivy([
        "trivy", "sbom", "--scanners", "license", "--format", "json",
        "--output", str(outputs["license_json"]), str(sbom_path)
    ], output_dir, log_file, outputs["license_json"]))

    records.append(_run_trivy([
        "trivy", "sbom", "--scanners", "license", "--format", "table",
        "--output", str(outputs["license_txt"]), str(sbom_path)
    ], output_dir, log_file, outputs["license_txt"]))

    records.append(_run_trivy([
        "trivy", "sbom", "--scanners", "vuln", "--format", "json",
        "--output", str(outputs["vuln_json"]), str(sbom_path)
    ], output_dir, log_file, outputs["vuln_json"]))

    added_to_report = augment_report_with_sbom_licenses(outputs["report_json"], sbom_path)
    added_to_license = augment_report_with_sbom_licenses(outputs["license_json"], sbom_path)
    if log_file and (added_to_report or added_to_license):
        with log_file.open("a", encoding="utf-8") as fh:
            fh.write(
                "\n[license-inventory]\n"
                f"Added {added_to_report} SBOM license rows to report.json\n"
                f"Added {added_to_license} SBOM license rows to license.json\n"
            )

    vuln_count, license_count = count_trivy_findings(outputs["report_json"])
    return outputs, vuln_count, license_count, records
