from __future__ import annotations

from pathlib import Path

from .config import IGNORE_DIR_NAMES, PROJECT_MARKERS
from .models import Project


def _has_suffix_marker(path: Path, suffix: str) -> list[str]:
    return [p.name for p in path.iterdir() if p.is_file() and p.name.endswith(suffix)]


def detect_project(path: Path) -> Project | None:
    path = path.resolve()
    if not path.is_dir():
        return None

    matches: list[tuple[str, list[str]]] = []
    for kind, markers in PROJECT_MARKERS.items():
        found: list[str] = []
        for marker in markers:
            if marker.startswith("."):
                found.extend(_has_suffix_marker(path, marker))
            elif (path / marker).exists():
                found.append(marker)
        if found:
            matches.append((kind, found))

    if not matches:
        return None

    priority = ("maven", "gradle", "dotnet", "flutter", "node", "python", "go", "php", "ruby")
    ranked = sorted(matches, key=lambda item: priority.index(item[0]) if item[0] in priority else 99)
    kind, markers = ranked[0]
    return Project(path=path, name=path.name, kind=kind, markers=sorted(set(markers)))


def discover_projects(root: Path, recursive_depth: int = 3) -> list[Project]:
    root = root.resolve()
    found: dict[Path, Project] = {}

    direct = detect_project(root)
    if direct:
        found[direct.path] = direct

    def walk(path: Path, depth: int) -> None:
        if depth > recursive_depth:
            return
        for child in sorted(path.iterdir()):
            if child.is_symlink() or not child.is_dir() or child.name in IGNORE_DIR_NAMES:
                continue
            project = detect_project(child)
            if project:
                found[project.path] = project
            walk(child, depth + 1)

    walk(root, 1)
    return sorted(found.values(), key=lambda project: str(project.path).lower())
