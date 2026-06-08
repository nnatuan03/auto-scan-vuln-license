from __future__ import annotations

import time
from pathlib import Path

from .detector import detect_project
from .license_normalizer import normalize_sbom
from .models import Project, ScanResult
from .reporting.reports import generate_single_report
from .sbom_generator import SbomGenerationError, generate_sbom
from .trivy_runner import TrivyScanError, scan_sbom
from .utils import ensure_dir


def scan_project(project: Project | Path, output_dir: Path, trivy_only: bool = False, dry_run: bool = False) -> ScanResult:
    if isinstance(project, Path):
        detected = detect_project(project)
        if not detected:
            detected = Project(path=project.resolve(), name=project.resolve().name, kind="unknown", markers=[])
        project = detected

    started = time.monotonic()
    ensure_dir(output_dir)
    log_file = output_dir / "scan.log"
    result = ScanResult(
        name=project.name,
        project_path=project.path,
        project_kind=project.kind,
        project_markers=sorted(set(project.markers)),
        output_dir=output_dir,
    )
    result.debug.update({
        "detected_kind": project.kind,
        "detected_markers": sorted(set(project.markers)),
        "source_path": str(project.path),
    })

    if dry_run:
        result.status = "DRYRUN"
        result.sbom_status = "not-run"
        result.notes.append(f"Detected {project.kind} project using markers: {', '.join(project.markers) or '-'}")
        result.elapsed_seconds = round(time.monotonic() - started, 3)
        return result

    try:
        sbom, sbom_status, sbom_commands = generate_sbom(project, output_dir, log_file, trivy_only=trivy_only)
        result.sbom_path = sbom
        result.sbom_status = sbom_status
        result.commands.extend(sbom_commands)
        result.debug["sbom_status"] = sbom_status
        result.debug["sbom_path"] = str(sbom)

        fixed_sbom = output_dir / "SBOM.cdx-fix.json"
        license_log = output_dir / "license-normalize.log"
        _, normalize_stats = normalize_sbom(sbom, fixed_sbom, license_log)
        result.fixed_sbom_path = fixed_sbom
        result.debug["license_normalize_stats"] = normalize_stats
        result.debug["fixed_sbom_path"] = str(fixed_sbom)

        outputs, vuln_count, license_count, trivy_commands = scan_sbom(fixed_sbom, output_dir, log_file)
        result.commands.extend(trivy_commands)
        result.report_json = outputs["report_json"]
        result.license_json = outputs["license_json"]
        result.license_txt = outputs["license_txt"]
        result.vuln_json = outputs["vuln_json"]
        result.vuln_count = vuln_count
        result.license_count = license_count
        result.debug["trivy_outputs"] = {key: str(path) for key, path in outputs.items()}

        result.report_html = generate_single_report(result.report_json, output_dir / "report.html")
        result.vuln_html = generate_single_report(result.vuln_json, output_dir / "report-vuln.html")
        result.debug["html_outputs"] = {
            "report_html": str(result.report_html),
            "vuln_html": str(result.vuln_html),
        }
        result.status = "OK"
    except (SbomGenerationError, TrivyScanError, OSError, ValueError) as exc:
        result.errors.append(str(exc))
        result.status = "FAIL"
        result.debug["error"] = str(exc)
    finally:
        result.elapsed_seconds = round(time.monotonic() - started, 3)

    return result
