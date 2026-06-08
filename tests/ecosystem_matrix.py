from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from autoscan.batch import scan_all
from autoscan.dependency_health import analyze_dependency_health
from autoscan.detector import discover_projects
from autoscan.models import Project
from autoscan.package_names import annotate_report_package_names
from autoscan.reporting.merge_report import generate_html as generate_merged_html
from autoscan.reporting.single_report import generate_html as generate_single_html


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.strip() + "\n", encoding="utf-8")


def create_matrix(root: Path) -> dict[str, str]:
    write(root / "maven-ok/pom.xml", """
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>maven-ok</artifactId>
  <version>1.0.0</version>
</project>
""")

    write(root / "gradle-ok/settings.gradle", "rootProject.name = 'gradle-ok'")
    write(root / "gradle-ok/build.gradle", """
plugins {
    id 'java'
}
""")

    write(root / "node-ok/package.json", """
{"name":"node-ok","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}
""")
    write(root / "node-ok/package-lock.json", """
{"lockfileVersion":3,"packages":{"":{"name":"node-ok","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}}}
""")

    write(root / "node-stale-lock/package.json", """
{"name":"node-stale-lock","version":"1.0.0","dependencies":{"left-pad":"1.3.0","lodash":"^4.17.21"}}
""")
    write(root / "node-stale-lock/package-lock.json", """
{"lockfileVersion":3,"packages":{"":{"name":"node-stale-lock","dependencies":{"left-pad":"1.3.0","lodash":"^4.17.21"}},"node_modules/left-pad":{"version":"1.1.0"}}}
""")

    write(root / "node-missing-lock/package.json", """
{"name":"node-missing-lock","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}
""")

    write(root / "flutter-ok/pubspec.yaml", """
name: flutter_ok
dependencies:
  http: 1.2.0
""")
    write(root / "flutter-ok/pubspec.lock", """
packages:
  http:
    dependency: "direct main"
    description:
      name: http
    source: hosted
    version: "1.2.0"
""")

    write(root / "flutter-stale-lock/pubspec.yaml", """
name: flutter_stale_lock
dependencies:
  http: 1.2.0
""")
    write(root / "flutter-stale-lock/pubspec.lock", """
packages:
  http:
    dependency: "direct main"
    description:
      name: http
    source: hosted
    version: "1.1.0"
""")

    write(root / "flutter-missing-lock/pubspec.yaml", """
name: flutter_missing_lock
dependencies:
  http: 1.2.0
""")

    write(root / "dotnet-missing-lock/app.csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup>
</Project>
""")

    write(root / "python-unpinned/requirements.txt", """
requests>=2.0
flask==3.0.0
""")

    write(root / "go-missing-sum/go.mod", """
module example.com/go-missing-sum

go 1.22

require github.com/google/uuid v1.6.0
""")

    write(root / "php-stale-lock/composer.json", """
{"require":{"monolog/monolog":"3.0.0"}}
""")
    write(root / "php-stale-lock/composer.lock", """
{"packages":[{"name":"monolog/monolog","version":"2.9.0"}]}
""")

    write(root / "ruby-stale-lock/Gemfile", """
source "https://rubygems.org"
gem "rack", "3.0.0"
""")
    write(root / "ruby-stale-lock/Gemfile.lock", """
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.0)
""")

    (root / "unknown-source").mkdir(parents=True, exist_ok=True)
    write(root / "unknown-source/src/main.txt", "plain source without dependency manifest")

    return {
        "maven-ok": "DEPENDENCY_HEALTH_OK",
        "gradle-ok": "DEPENDENCY_HEALTH_OK",
        "node-ok": "DEPENDENCY_HEALTH_OK",
        "node-stale-lock": "MANIFEST_LOCK_MISMATCH",
        "node-missing-lock": "LOCK_FILE_MISSING",
        "flutter-ok": "DEPENDENCY_HEALTH_OK",
        "flutter-stale-lock": "MANIFEST_LOCK_MISMATCH",
        "flutter-missing-lock": "LOCK_FILE_MISSING",
        "dotnet-missing-lock": "LOCK_FILE_MISSING",
        "python-unpinned": "UNPINNED_DEPENDENCY",
        "go-missing-sum": "LOCK_FILE_MISSING",
        "php-stale-lock": "MANIFEST_LOCK_MISMATCH",
        "ruby-stale-lock": "MANIFEST_LOCK_MISMATCH",
        "unknown-source": "BUILD_FILE_MISSING",
    }


def assert_dependency_health_matrix(root: Path, expected: dict[str, str]) -> None:
    projects = discover_projects(root, recursive_depth=2)
    by_name = {project.name: project for project in projects}
    missing = sorted(set(expected) - set(by_name))
    assert not missing, f"Projects not detected: {missing}"

    actual: dict[str, str] = {}
    for name, project in by_name.items():
        health = analyze_dependency_health(project)
        actual[name] = str(health["status"])
    for name, status in sorted(expected.items()):
        assert actual.get(name) == status, f"{name}: expected {status}, got {actual.get(name)}"


def assert_dry_run_debug(root: Path, expected: dict[str, str], output: Path) -> None:
    run_dir, results, merged = scan_all(
        root=root,
        output_base=output,
        recursive_depth=2,
        dry_run=True,
        max_workers=4,
    )
    assert merged is None
    by_name = {result.name: result for result in results}
    for name, status in sorted(expected.items()):
        health = by_name[name].debug.get("dependency_health") or {}
        assert health.get("status") == status, f"{name}: dry-run health mismatch"

    debug_md = (run_dir / "debug-report.md").read_text(encoding="utf-8")
    for status in set(expected.values()):
        assert status in debug_md, f"{status} missing from debug report"


def assert_report_package_name_recovery(output: Path) -> None:
    services_dir = output / "services"
    service_dir = services_dir / "pkg-name-recovery"
    service_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "Metadata": {
            "AutoScan": {
                "dependency_health": {
                    "status": "MANIFEST_LOCK_MISMATCH",
                    "manifest_files": ["package.json"],
                    "lock_files": ["package-lock.json"],
                    "issues": [
                        {
                            "code": "MANIFEST_LOCK_MISMATCH",
                            "message": "package.json declares @angular/core 1.84.0 but lock resolves 1.80.0.",
                            "dependency": "@angular/core",
                            "declared": "1.84.0",
                            "resolved": "1.80.0",
                            "lock_file": "package-lock.json",
                        }
                    ],
                }
            }
        },
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Vulnerabilities": [
                    {
                        "PkgIdentifier": {"PURL": "pkg:npm/%40angular/core@1.80.0"},
                        "InstalledVersion": "1.80.0",
                        "VulnerabilityID": "CVE-2026-0001",
                        "Severity": "HIGH",
                        "Title": "sample",
                    }
                ],
                "Licenses": [
                    {
                        "FilePath": "node_modules/@scope/ui/LICENSE",
                        "Name": "MIT",
                        "Severity": "LOW",
                        "Category": "permissive",
                    }
                ],
            },
            {
                "Target": "Loose File License(s)",
                "Class": "license-file",
                "Licenses": [
                    {
                        "FilePath": "licenses/cddl_gplv2+ce - license.html",
                        "Name": "CDDL-1.1",
                        "Severity": "MEDIUM",
                        "Category": "reciprocal",
                    }
                ],
            },
        ],
    }
    stats = annotate_report_package_names(report)
    assert stats["vulnerabilities"]["resolved_from_fallback"] == 1
    assert stats["licenses"]["resolved_from_fallback"] == 2

    report_path = service_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    generate_single_html(str(report_path), str(service_dir / "report.html"))
    generate_merged_html(str(services_dir), str(output / "consolidated-report.html"))

    html = (service_dir / "report.html").read_text(encoding="utf-8")
    merged = (output / "consolidated-report.html").read_text(encoding="utf-8")
    for expected in (
        "@angular/core",
        "@scope/ui",
        "Loose File License(s)",
        "Dependency Health: MANIFEST_LOCK_MISMATCH",
    ):
        assert expected in html, f"{expected} missing from single report"
    assert "MANIFEST_LOCK_MISMATCH" in merged


def main() -> int:
    temp_dir = Path(tempfile.mkdtemp(prefix="autoscan-ecosystem-matrix-"))
    try:
        source_root = temp_dir / "source"
        output_root = temp_dir / "output"
        expected = create_matrix(source_root)
        assert_dependency_health_matrix(source_root, expected)
        assert_dry_run_debug(source_root, expected, output_root / "dry-run")
        assert_report_package_name_recovery(output_root / "reports")
        print("ecosystem-matrix-ok")
        for name, status in sorted(expected.items()):
            print(f"{name}: {status}")
        return 0
    finally:
        if "--keep" not in sys.argv:
            shutil.rmtree(temp_dir, ignore_errors=True)
        else:
            print(f"kept: {temp_dir}")


if __name__ == "__main__":
    raise SystemExit(main())
