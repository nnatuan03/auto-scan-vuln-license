from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .config import DEFAULT_RESULTS_DIR
from .debug_report import write_debug_reports
from .dependency_preparer import prepare_dependencies
from .detector import discover_projects
from .maven_prebuild import prebuild_internal_maven_projects
from .models import Project, ScanResult
from .reporting.reports import generate_merged_report
from .scanner import scan_project
from .utils import ensure_dir, safe_name, write_json

ProgressCallback = Callable[[str, dict[str, Any]], None]


def make_run_dir(base_output_dir: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = base_output_dir / timestamp
    suffix = 1
    while run_dir.exists():
        suffix += 1
        run_dir = base_output_dir / f"{timestamp}-{suffix}"
    return ensure_dir(run_dir)


def scan_all(
    root: Path,
    output_base: Path | None = None,
    max_workers: int = 4,
    recursive_depth: int = 3,
    trivy_only: bool = False,
    dry_run: bool = False,
    maven_prebuild: bool = True,
    prepare_deps: bool = False,
    prepare_deps_auto: bool = False,
    progress_callback: ProgressCallback | None = None,
) -> tuple[Path, list[ScanResult], Path | None]:
    root = root.resolve()
    default_output_parent = root if root.is_dir() else root.parent
    output_base = (output_base or (default_output_parent / DEFAULT_RESULTS_DIR)).resolve()
    ensure_dir(output_base)
    run_dir = make_run_dir(output_base)
    services_dir = ensure_dir(run_dir / "services")

    if root.is_file():
        projects = [Project(path=root, name=root.name, kind="file", markers=[root.name])]
    else:
        projects = discover_projects(root, recursive_depth=recursive_depth)
    if progress_callback:
        progress_callback("start", {
            "root": root,
            "run_dir": run_dir,
            "total": len(projects),
            "projects": projects,
        })
    if not projects:
        debug_paths = write_debug_reports(root, run_dir, output_base, [], None, dry_run, {})
        summary = {
            "root": str(root),
            "run_dir": str(run_dir),
            "status": "NO_PROJECTS",
            "debug_report": str(debug_paths["debug_report"]),
            "debug_report_json": str(debug_paths["debug_report_json"]),
            "stable_debug_report": str(debug_paths["stable_debug_report"]),
            "stable_debug_report_json": str(debug_paths["stable_debug_report_json"]),
            "projects": [],
        }
        write_json(run_dir / "scan-summary.json", summary)
        write_json(output_base / "scan-summary.json", summary)
        if progress_callback:
            progress_callback("finish", {
                "completed": 0,
                "ok": 0,
                "failed": 0,
                "debug_report": debug_paths["debug_report"],
            })
        return run_dir, [], None

    if progress_callback:
        progress_callback("prebuild_start", {
            "projects": projects,
        })
    dependency_prepare_results, dependency_prepare_commands = prepare_dependencies(
        projects,
        run_dir / "dependency-prepare.log",
        enabled=prepare_deps and not dry_run,
        assume_yes=prepare_deps_auto,
    )
    maven_prebuild_summary = prebuild_internal_maven_projects(
        projects,
        run_dir,
        enabled=maven_prebuild and root.is_dir(),
        dry_run=dry_run,
        trivy_only=trivy_only,
    )
    if progress_callback:
        progress_callback("prebuild_complete", {
            "summary": maven_prebuild_summary,
        })

    results: list[ScanResult] = []
    name_counts: dict[str, int] = {}
    for project in projects:
        name_counts[project.name] = name_counts.get(project.name, 0) + 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {}
        for project in projects:
            try:
                relative_name = str(project.path.relative_to(root if root.is_dir() else root.parent))
            except ValueError:
                relative_name = project.name
            if relative_name == ".":
                relative_name = project.name
            service_dir = services_dir / safe_name(relative_name)
            scan_project_input = project
            if name_counts.get(project.name, 0) > 1:
                scan_project_input = Project(
                    path=project.path,
                    name=relative_name.replace("\\", "/"),
                    kind=project.kind,
                    markers=project.markers,
                )
            future = executor.submit(scan_project, scan_project_input, service_dir, trivy_only, dry_run)
            future_map[future] = project

        for future in as_completed(future_map):
            results.append(future.result())
            if progress_callback:
                progress_callback("project_complete", {
                    "result": results[-1],
                    "completed": len(results),
                    "ok": sum(1 for r in results if r.status == "OK"),
                    "failed": sum(1 for r in results if r.status == "FAIL"),
                })

    results.sort(key=lambda r: r.name.lower())
    merged_report: Path | None = None
    if not dry_run and any(r.status == "OK" for r in results):
        if progress_callback:
            progress_callback("merge_start", {
                "completed": len(results),
                "ok": sum(1 for r in results if r.status == "OK"),
                "failed": sum(1 for r in results if r.status == "FAIL"),
            })
        merged_report = generate_merged_report(services_dir, run_dir / "consolidated-report.html")
        shutil.copy2(merged_report, output_base / "consolidated-report.html")

    debug_paths = write_debug_reports(root, run_dir, output_base, results, merged_report, dry_run, maven_prebuild_summary)
    summary = {
        "root": str(root),
        "run_dir": str(run_dir),
        "consolidated_report": str(merged_report) if merged_report else None,
        "stable_consolidated_report": str(output_base / "consolidated-report.html") if merged_report else None,
        "debug_report": str(debug_paths["debug_report"]),
        "debug_report_json": str(debug_paths["debug_report_json"]),
        "stable_debug_report": str(debug_paths["stable_debug_report"]),
        "stable_debug_report_json": str(debug_paths["stable_debug_report_json"]),
        "total_projects": len(results),
        "ok": sum(1 for r in results if r.status == "OK"),
        "failed": sum(1 for r in results if r.status == "FAIL"),
        "dry_run": dry_run,
        "dependency_prepare": [item.to_json() for item in dependency_prepare_results],
        "dependency_prepare_commands": [command.to_json() for command in dependency_prepare_commands],
        "maven_prebuild": maven_prebuild_summary,
        "projects": [r.to_json() for r in results],
    }
    write_json(run_dir / "scan-summary.json", summary)
    write_json(output_base / "scan-summary.json", summary)
    if progress_callback:
        progress_callback("finish", {
            "completed": len(results),
            "ok": summary["ok"],
            "failed": summary["failed"],
            "merged_report": merged_report,
            "debug_report": debug_paths["debug_report"],
        })
    return run_dir, results, merged_report
