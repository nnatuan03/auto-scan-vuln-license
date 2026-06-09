from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Project
from .utils import first_existing_tool, run_command


@dataclass(frozen=True)
class MavenCoordinate:
    group_id: str
    artifact_id: str
    version: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return self.group_id, self.artifact_id

    def text(self) -> str:
        if self.version:
            return f"{self.group_id}:{self.artifact_id}:{self.version}"
        return f"{self.group_id}:{self.artifact_id}"


@dataclass
class MavenProjectInfo:
    project: Project
    coordinate: MavenCoordinate
    packaging: str = "jar"
    parent: MavenCoordinate | None = None
    dependencies: list[MavenCoordinate] = field(default_factory=list)
    parse_error: str | None = None


def prebuild_internal_maven_projects(
    projects: list[Project],
    run_dir: Path,
    *,
    enabled: bool = True,
    dry_run: bool = False,
    trivy_only: bool = False,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "enabled": enabled,
        "skipped": False,
        "skip_reason": "",
        "log": str(run_dir / "maven-prebuild.log"),
        "maven_projects": 0,
        "internal_build_projects": [],
        "installed": [],
        "failed": [],
        "parse_errors": [],
        "commands": [],
    }
    maven_projects = [project for project in projects if project.kind == "maven"]
    summary["maven_projects"] = len(maven_projects)
    if not enabled:
        summary["skipped"] = True
        summary["skip_reason"] = "disabled by --skip-maven-prebuild"
        return summary
    if trivy_only:
        summary["skipped"] = True
        summary["skip_reason"] = "trivy-only mode"
        return summary
    if len(maven_projects) < 2:
        summary["skipped"] = True
        summary["skip_reason"] = "fewer than two Maven projects detected"
        return summary

    plan = plan_internal_maven_prebuilds(maven_projects)
    summary["parse_errors"] = plan["parse_errors"]
    ordered = plan["projects"]
    summary["internal_build_projects"] = [
        {
            "project": info.project.name,
            "path": str(info.project.path),
            "coordinate": info.coordinate.text(),
            "packaging": info.packaging,
        }
        for info in ordered
    ]
    if not ordered:
        summary["skipped"] = True
        summary["skip_reason"] = "no Maven project depends on another Maven project in this source folder"
        return summary
    if dry_run:
        summary["skipped"] = True
        summary["skip_reason"] = "dry-run"
        return summary

    log_file = run_dir / "maven-prebuild.log"
    for info in ordered:
        command = _maven_install_command(info.project)
        if not command:
            summary["failed"].append({
                "project": info.project.name,
                "coordinate": info.coordinate.text(),
                "error": "mvn/mvnw was not found",
            })
            continue
        record, stdout, stderr = run_command(command, cwd=info.project.path, log_file=log_file)
        summary["commands"].append(record.to_json())
        item = {
            "project": info.project.name,
            "path": str(info.project.path),
            "coordinate": info.coordinate.text(),
            "returncode": record.returncode,
        }
        if record.returncode == 0:
            summary["installed"].append(item)
        else:
            missing_pom_warnings = _missing_pom_warnings(stdout + "\n" + stderr)
            if missing_pom_warnings:
                item["missing_pom_warnings"] = missing_pom_warnings
            summary["failed"].append(item)
    return summary


def plan_internal_maven_prebuilds(maven_projects: list[Project]) -> dict[str, Any]:
    infos = [_read_maven_project(project) for project in maven_projects]
    parse_errors = [
        {
            "project": info.project.name,
            "path": str(info.project.path),
            "error": info.parse_error,
        }
        for info in infos
        if info.parse_error
    ]
    infos = [info for info in infos if not info.parse_error]
    by_key = {info.coordinate.key: info for info in infos if info.coordinate.group_id and info.coordinate.artifact_id}
    selected = _select_internal_builds(infos, by_key)
    ordered = _topological_order(selected, by_key)
    return {"projects": ordered, "parse_errors": parse_errors}


def _select_internal_builds(
    infos: list[MavenProjectInfo],
    by_key: dict[tuple[str, str], MavenProjectInfo],
) -> list[MavenProjectInfo]:
    selected_keys: set[tuple[str, str]] = set()
    for info in infos:
        for dependency in info.dependencies:
            if dependency.key in by_key and dependency.key != info.coordinate.key:
                selected_keys.add(dependency.key)
    changed = True
    while changed:
        changed = False
        for key in list(selected_keys):
            info = by_key.get(key)
            if not info:
                continue
            if info.parent and info.parent.key in by_key and info.parent.key not in selected_keys:
                selected_keys.add(info.parent.key)
                changed = True
            for dependency in info.dependencies:
                if dependency.key in by_key and dependency.key not in selected_keys:
                    selected_keys.add(dependency.key)
                    changed = True
    return [by_key[key] for key in selected_keys if key in by_key]


def _topological_order(
    selected: list[MavenProjectInfo],
    by_key: dict[tuple[str, str], MavenProjectInfo],
) -> list[MavenProjectInfo]:
    selected_keys = {info.coordinate.key for info in selected}
    ordered: list[MavenProjectInfo] = []
    visiting: set[tuple[str, str]] = set()
    visited: set[tuple[str, str]] = set()

    def visit(info: MavenProjectInfo) -> None:
        key = info.coordinate.key
        if key in visited:
            return
        if key in visiting:
            return
        visiting.add(key)
        upstream: list[MavenCoordinate] = []
        if info.parent:
            upstream.append(info.parent)
        upstream.extend(info.dependencies)
        for coordinate in upstream:
            dep = by_key.get(coordinate.key)
            if dep and dep.coordinate.key in selected_keys:
                visit(dep)
        visiting.remove(key)
        visited.add(key)
        ordered.append(info)

    for info in sorted(selected, key=lambda item: (len(item.project.path.parts), str(item.project.path).lower())):
        visit(info)
    return ordered


def _read_maven_project(project: Project) -> MavenProjectInfo:
    pom = project.path / "pom.xml"
    try:
        root = ET.parse(pom).getroot()
    except (OSError, ET.ParseError) as exc:
        return MavenProjectInfo(
            project=project,
            coordinate=MavenCoordinate("", ""),
            parse_error=str(exc),
        )

    parent = _parent_coordinate(root)
    group_id = _direct_text(root, "groupId") or (parent.group_id if parent else "")
    artifact_id = _direct_text(root, "artifactId")
    version = _direct_text(root, "version") or (parent.version if parent else "")
    packaging = _direct_text(root, "packaging") or "jar"
    dependencies = _dependency_coordinates(root, group_id, version)
    return MavenProjectInfo(
        project=project,
        coordinate=MavenCoordinate(group_id, artifact_id, version),
        packaging=packaging,
        parent=parent,
        dependencies=dependencies,
    )


def _maven_install_command(project: Project) -> list[str] | None:
    for wrapper in ("mvnw.cmd", "mvnw"):
        candidate = project.path / wrapper
        if candidate.is_file():
            return [
                str(candidate),
                "clean",
                "install",
                "-DskipTests",
                "-Dmaven.test.skip=true",
                "-DskipITs",
            ]
    mvn = first_existing_tool(("mvn.cmd", "mvn"))
    if not mvn:
        return None
    return [
        mvn,
        "clean",
        "install",
        "-DskipTests",
        "-Dmaven.test.skip=true",
        "-DskipITs",
    ]


def _parent_coordinate(root: ET.Element) -> MavenCoordinate | None:
    parent = _direct_child(root, "parent")
    if parent is None:
        return None
    group_id = _direct_text(parent, "groupId")
    artifact_id = _direct_text(parent, "artifactId")
    version = _direct_text(parent, "version")
    if not group_id or not artifact_id:
        return None
    return MavenCoordinate(group_id, artifact_id, version)


def _dependency_coordinates(root: ET.Element, project_group: str, project_version: str) -> list[MavenCoordinate]:
    dependencies: list[MavenCoordinate] = []
    for dependencies_node in _direct_children(root, "dependencies"):
        for dependency in _direct_children(dependencies_node, "dependency"):
            group_id = _resolve_property(_direct_text(dependency, "groupId"), project_group, project_version)
            artifact_id = _resolve_property(_direct_text(dependency, "artifactId"), project_group, project_version)
            version = _resolve_property(_direct_text(dependency, "version"), project_group, project_version)
            if group_id and artifact_id:
                dependencies.append(MavenCoordinate(group_id, artifact_id, version))
    return dependencies


def _resolve_property(value: str, project_group: str, project_version: str) -> str:
    if value == "${project.groupId}" or value == "${pom.groupId}":
        return project_group
    if value == "${project.version}" or value == "${pom.version}":
        return project_version
    return value


def _direct_child(element: ET.Element, local_name: str) -> ET.Element | None:
    for child in list(element):
        if _local_name(child.tag) == local_name:
            return child
    return None


def _direct_children(element: ET.Element, local_name: str) -> list[ET.Element]:
    return [child for child in list(element) if _local_name(child.tag) == local_name]


def _direct_text(element: ET.Element, local_name: str) -> str:
    child = _direct_child(element, local_name)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _missing_pom_warnings(output: str) -> list[str]:
    warnings: list[str] = []
    for line in output.splitlines():
        if "The POM for " in line and " is missing" in line:
            warnings.append(line.strip())
    return warnings[:20]
