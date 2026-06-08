from __future__ import annotations

from pathlib import Path

from .config import IGNORE_DIR_NAMES, PROJECT_MARKERS
from .models import Project

FLUTTER_PLATFORM_DIR_NAMES = {
    ".dart_tool",
    "android",
    "ios",
    "linux",
    "macos",
    "web",
    "windows",
}


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


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def discover_projects(root: Path, recursive_depth: int = 3) -> list[Project]:
    root = root.resolve()
    found: dict[Path, Project] = {}

    direct = detect_project(root)
    if direct:
        found[direct.path] = direct

    top_level_dirs = [
        child for child in sorted(root.iterdir())
        if child.is_dir() and not child.is_symlink() and child.name not in IGNORE_DIR_NAMES
    ]

    def walk(path: Path, depth: int, skip_child_names: set[str] | None = None) -> None:
        if depth > recursive_depth:
            return
        skip_child_names = skip_child_names or set()
        for child in sorted(path.iterdir()):
            if child.is_symlink() or not child.is_dir() or child.name in IGNORE_DIR_NAMES or child.name in skip_child_names:
                continue
            project = detect_project(child)
            nested_skip: set[str] | None = None
            if project:
                found[project.path] = project
                if project.kind == "flutter":
                    nested_skip = FLUTTER_PLATFORM_DIR_NAMES
            walk(child, depth + 1, nested_skip)

    walk(root, 1)
    if direct is None:
        for child in top_level_dirs:
            has_project_inside = any(_is_under(project_path, child) for project_path in found)
            if not has_project_inside:
                found[child.resolve()] = Project(
                    path=child.resolve(),
                    name=child.name,
                    kind="unknown",
                    markers=[],
                )
    return sorted(found.values(), key=lambda project: str(project.path).lower())
