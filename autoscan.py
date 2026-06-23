from __future__ import annotations

import argparse
import sys
from pathlib import Path

from autoscan.batch import scan_all
from autoscan.config import DEFAULT_MAX_WORKERS, DEFAULT_RECURSIVE_DEPTH
from autoscan.detector import discover_projects
from autoscan.progress import ProgressDashboard
from autoscan.terminal import configure_terminal, status_label
from autoscan.tool_installer import ToolRequirement, detect_missing_tools, install_missing_tools, missing_tools_from_results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Auto-detect source type, generate SBOM, scan dependency/license, and create final reports.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Project folder, single file, or parent folder containing services.")
    parser.add_argument("-o", "--output", help="Output base directory. Default: <path>/scan-results.")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Parallel project scans.")
    parser.add_argument("--recursive-depth", type=int, default=DEFAULT_RECURSIVE_DEPTH, help="Project discovery depth for nested services/workspaces.")
    parser.add_argument("--trivy-only", action="store_true", help="Skip ecosystem-specific SBOM generators and use trivy fs only.")
    parser.add_argument("--skip-maven-prebuild", action="store_true", help="Do not prebuild local Maven libraries before scanning Maven services.")
    parser.add_argument("--dry-run", action="store_true", help="Only detect projects; do not run external scan commands.")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable the console progress dashboard.")
    parser.add_argument("--hide-commands", action="store_true", help="Do not print each external command to the terminal.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output.")
    parser.add_argument("--install-missing", action="store_true", help="Install missing scan tools automatically when a supported package manager is available.")
    parser.add_argument("--no-install-prompt", action="store_true", help="Do not ask to install missing scan tools.")
    parser.add_argument("--prepare-deps", action="store_true", help="Ask to run dependency preparation commands for missing lock/metadata before scanning.")
    parser.add_argument("--prepare-deps-auto", action="store_true", help="Run dependency preparation commands automatically before scanning.")
    return parser


def _projects_for_preflight(root: Path, recursive_depth: int):
    if root.is_file():
        from autoscan.models import Project
        return [Project(path=root, name=root.name, kind="file", markers=[root.name])]
    return discover_projects(root, recursive_depth=recursive_depth)


def _install_preflight_tools(args: argparse.Namespace, root: Path) -> None:
    if args.no_install_prompt:
        return
    projects = _projects_for_preflight(root, max(0, args.recursive_depth))
    missing = detect_missing_tools(
        projects,
        trivy_only=args.trivy_only,
        maven_prebuild=not args.skip_maven_prebuild,
        dry_run=args.dry_run,
    )
    if missing:
        install_missing_tools(missing, assume_yes=args.install_missing)


def _install_after_missing_tool_failure(args: argparse.Namespace, failed_tools: list[str]) -> bool:
    if args.no_install_prompt or not failed_tools:
        return False
    requirements = [
        ToolRequirement(
            tool=tool,
            package=tool,
            reason="The previous scan failed because this tool was missing.",
            required=True,
        )
        for tool in failed_tools
    ]
    return install_missing_tools(requirements, assume_yes=args.install_missing)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not (root.is_dir() or root.is_file()):
        print(f"[ERROR] Path is not a file or directory: {root}", file=sys.stderr)
        return 2

    output = Path(args.output).expanduser().resolve() if args.output else None
    configure_terminal(
        show_commands=not args.hide_commands,
        color_mode="never" if args.no_color else "auto",
    )
    _install_preflight_tools(args, root)
    dashboard = ProgressDashboard(enabled=not args.no_dashboard)
    run_dir, results, merged = scan_all(
        root=root,
        output_base=output,
        max_workers=max(1, args.max_workers),
        recursive_depth=max(0, args.recursive_depth),
        trivy_only=args.trivy_only,
        dry_run=args.dry_run,
        maven_prebuild=not args.skip_maven_prebuild,
        prepare_deps=args.prepare_deps or args.prepare_deps_auto,
        prepare_deps_auto=args.prepare_deps_auto,
        progress_callback=dashboard,
    )
    failed_tools = missing_tools_from_results(results)
    if _install_after_missing_tool_failure(args, failed_tools):
        print("\n[INFO] Missing tools installed. Re-running scan once...\n")
        dashboard = ProgressDashboard(enabled=not args.no_dashboard)
        run_dir, results, merged = scan_all(
            root=root,
            output_base=output,
            max_workers=max(1, args.max_workers),
            recursive_depth=max(0, args.recursive_depth),
            trivy_only=args.trivy_only,
            dry_run=args.dry_run,
            maven_prebuild=not args.skip_maven_prebuild,
            prepare_deps=args.prepare_deps or args.prepare_deps_auto,
            prepare_deps_auto=args.prepare_deps_auto,
            progress_callback=dashboard,
        )

    print("")
    print("Auto Scan Summary")
    print("=================")
    print(f"Root       : {root}")
    print(f"Run output : {run_dir}")
    print(f"Projects   : {len(results)}")
    print(f"OK         : {sum(1 for r in results if r.status == 'OK')}")
    print(f"FAIL       : {sum(1 for r in results if r.status == 'FAIL')}")
    if args.dry_run:
        print("Mode       : dry-run")
    if merged:
        print(f"Report     : {merged}")
        print(f"Stable copy: {run_dir.parent / 'consolidated-report.html'}")
    debug_report = run_dir / "debug-report.md"
    stable_debug_report = run_dir.parent / "debug-report.md"
    if debug_report.is_file():
        print(f"Debug      : {debug_report}")
        print(f"Stable dbg : {stable_debug_report}")
    print("")

    if not results:
        print("[WARN] No project folders detected.")
        return 1

    for result in results:
        status = result.status
        details = (
            f"{result.name} [{result.project_kind}] "
            f"sbom_vulns={result.vuln_count} sbom_licenses={result.license_count} "
            f"fs_vulns={result.filesystem_vuln_count} fs_licenses={result.filesystem_license_count} "
            f"misconfigs={result.misconfig_count} secrets={result.secret_count} "
            f"sbom={result.sbom_status}"
        )
        print(f"[{status_label(status)}] {details}")
        for err in result.errors:
            print(f"       error: {err}")

    return 0 if all(r.status in ("OK", "DRYRUN") for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
