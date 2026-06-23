from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .models import Project, ScanResult

PromptFn = Callable[[str], str]


@dataclass(frozen=True)
class ToolRequirement:
    tool: str
    package: str
    reason: str
    required: bool = False


INSTALL_PACKAGES: dict[str, dict[str, str]] = {
    "trivy": {
        "brew": "trivy",
        "winget": "AquaSecurity.Trivy",
        "apt": "trivy",
    },
    "maven": {
        "brew": "maven",
        "winget": "Apache.Maven",
        "apt": "maven",
    },
    "gradle": {
        "brew": "gradle",
        "winget": "Gradle.Gradle",
        "apt": "gradle",
    },
    "node": {
        "brew": "node",
        "winget": "OpenJS.NodeJS.LTS",
        "apt": "nodejs",
    },
    "dotnet": {
        "brew": "dotnet-sdk",
        "winget": "Microsoft.DotNet.SDK.8",
        "apt": "dotnet-sdk-8.0",
    },
    "flutter": {
        "brew": "--cask flutter",
        "winget": "Google.Flutter",
    },
}


def _which_any(names: Iterable[str]) -> bool:
    return any(shutil.which(name) for name in names)


def detect_missing_tools(projects: list[Project], *, trivy_only: bool, maven_prebuild: bool, dry_run: bool) -> list[ToolRequirement]:
    if dry_run:
        return []

    missing: list[ToolRequirement] = []
    if not _which_any(("trivy",)):
        missing.append(ToolRequirement(
            tool="trivy",
            package="trivy",
            reason="Required for SBOM fallback, full filesystem scan, vulnerability/license/secret/misconfig scanning.",
            required=True,
        ))

    if trivy_only:
        return missing

    kinds = {project.kind for project in projects}
    project_paths = [project.path for project in projects if project.path.is_dir()]

    if "maven" in kinds and not any((path / "mvnw").is_file() or (path / "mvnw.cmd").is_file() for path in project_paths) and not _which_any(("mvn", "mvn.cmd")):
        missing.append(ToolRequirement("maven", "maven", "Recommended for accurate Maven SBOM generation and internal Maven prebuild.", required=maven_prebuild))
    if "gradle" in kinds and not any((path / "gradlew").is_file() or (path / "gradlew.bat").is_file() for path in project_paths) and not _which_any(("gradle", "gradle.bat")):
        missing.append(ToolRequirement("gradle", "gradle", "Recommended for accurate Gradle SBOM generation."))
    if "node" in kinds and not _which_any(("npx", "npx.cmd")):
        missing.append(ToolRequirement("node", "node", "Recommended for npm lock based CycloneDX SBOM generation."))
    if "dotnet" in kinds and not _which_any(("dotnet-CycloneDX", "dotnet-CycloneDX.exe", "dotnet", "dotnet.exe")):
        missing.append(ToolRequirement("dotnet", "dotnet", "Recommended for .NET CycloneDX SBOM generation."))
    if "flutter" in kinds and not _which_any(("flutter", "flutter.bat")):
        missing.append(ToolRequirement("flutter", "flutter", "Recommended to run flutter pub get when pubspec.lock is missing."))

    return missing


def missing_tools_from_results(results: list[ScanResult]) -> list[str]:
    tools: list[str] = []
    for result in results:
        for error in result.errors:
            text = error.lower()
            for tool in INSTALL_PACKAGES:
                if f"{tool} not found" in text or f"{tool} not found in path" in text:
                    if tool not in tools:
                        tools.append(tool)
    return tools


def supported_package_manager() -> str | None:
    system = platform.system().lower()
    if shutil.which("brew"):
        return "brew"
    if system == "windows" and shutil.which("winget"):
        return "winget"
    if system == "linux" and shutil.which("apt-get"):
        return "apt"
    return None


def install_command(manager: str, package: str) -> list[str] | None:
    if manager == "brew":
        if package.startswith("--cask "):
            return ["brew", "install", "--cask", package.split(" ", 1)[1]]
        return ["brew", "install", package]
    if manager == "winget":
        return ["winget", "install", "--id", package, "--accept-package-agreements", "--accept-source-agreements"]
    if manager == "apt":
        return ["sudo", "apt-get", "install", "-y", package]
    return None


def _confirm_install(requirements: list[ToolRequirement], *, prompt: PromptFn = input) -> bool:
    print("\nMissing scan tools detected:")
    for item in requirements:
        level = "required" if item.required else "recommended"
        print(f"- {item.tool} ({level}): {item.reason}")
    answer = prompt("Install missing tools now and then run the scan? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def install_missing_tools(requirements: list[ToolRequirement], *, assume_yes: bool = False, prompt: PromptFn = input) -> bool:
    if not requirements:
        return True

    manager = supported_package_manager()
    if not manager:
        print("[WARN] No supported package manager found (brew, winget, or apt-get). Please install tools manually.", file=sys.stderr)
        return False

    if not assume_yes and not sys.stdin.isatty():
        tools = ", ".join(item.tool for item in requirements)
        print(f"[WARN] Missing scan tools detected ({tools}) but stdin is not interactive. Re-run with --install-missing or install them manually.", file=sys.stderr)
        return False

    if not assume_yes and not _confirm_install(requirements, prompt=prompt):
        return False

    seen: set[str] = set()
    for item in requirements:
        package = INSTALL_PACKAGES.get(item.package, {}).get(manager)
        if not package or package in seen:
            continue
        seen.add(package)
        command = install_command(manager, package)
        if not command:
            continue
        print(f"[INSTALL] {' '.join(command)}")
        completed = subprocess.run(command, check=False)
        if completed.returncode != 0:
            print(f"[WARN] Install failed for {item.tool} with exit code {completed.returncode}.", file=sys.stderr)
            return False
    return True
