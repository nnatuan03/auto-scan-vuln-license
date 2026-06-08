from __future__ import annotations

import argparse
import sys
from pathlib import Path

from autoscan.batch import scan_all
from autoscan.config import DEFAULT_MAX_WORKERS, DEFAULT_RECURSIVE_DEPTH
from autoscan.progress import ProgressDashboard
from autoscan.terminal import configure_terminal, status_label


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Auto-detect source type, generate SBOM, scan dependency/license, and create final reports.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Project folder or parent folder containing services.")
    parser.add_argument("-o", "--output", help="Output base directory. Default: <path>/scan-results.")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Parallel project scans.")
    parser.add_argument("--recursive-depth", type=int, default=DEFAULT_RECURSIVE_DEPTH, help="Project discovery depth for nested services/workspaces.")
    parser.add_argument("--trivy-only", action="store_true", help="Skip ecosystem-specific SBOM generators and use trivy fs only.")
    parser.add_argument("--dry-run", action="store_true", help="Only detect projects; do not run external scan commands.")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable the console progress dashboard.")
    parser.add_argument("--hide-commands", action="store_true", help="Do not print each external command to the terminal.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"[ERROR] Path is not a directory: {root}", file=sys.stderr)
        return 2

    output = Path(args.output).expanduser().resolve() if args.output else None
    configure_terminal(
        show_commands=not args.hide_commands,
        color_mode="never" if args.no_color else "auto",
    )
    dashboard = ProgressDashboard(enabled=not args.no_dashboard)
    run_dir, results, merged = scan_all(
        root=root,
        output_base=output,
        max_workers=max(1, args.max_workers),
        recursive_depth=max(0, args.recursive_depth),
        trivy_only=args.trivy_only,
        dry_run=args.dry_run,
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
        details = f"{result.name} [{result.project_kind}] vulns={result.vuln_count} licenses={result.license_count} sbom={result.sbom_status}"
        print(f"[{status_label(status)}] {details}")
        for err in result.errors:
            print(f"       error: {err}")

    return 0 if all(r.status in ("OK", "DRYRUN") for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
