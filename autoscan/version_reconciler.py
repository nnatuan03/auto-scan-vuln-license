from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import Project
from .utils import ensure_dir


VERSION_RE = re.compile(r"\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?")
YARN_ENTRY_RE = re.compile(r'^"?([^":]+?)"?\s*:\s*$')
YARN_VERSION_RE = re.compile(r'^\s*version\s+"([^"]+)"\s*$')
PUBSPEC_NAME_RE = re.compile(r"^\s{2}([A-Za-z0-9_.-]+):\s*$")
PUBSPEC_VERSION_RE = re.compile(r'^\s{4}version:\s+"?([^"\s]+)"?\s*$')


def _version_key(version: str) -> tuple[int, ...]:
    match = VERSION_RE.search(str(version or ""))
    if not match:
        return ()
    return tuple(int(part) for part in re.findall(r"\d+", match.group(0).split("-", 1)[0].split("+", 1)[0]))


def _newer_version(left: str, right: str) -> str:
    left_key = _version_key(left)
    right_key = _version_key(right)
    if not left_key:
        return right
    if not right_key:
        return left
    width = max(len(left_key), len(right_key))
    if left_key + (0,) * (width - len(left_key)) >= right_key + (0,) * (width - len(right_key)):
        return left
    return right


def _candidate_version(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = VERSION_RE.search(value)
    return match.group(0) if match else None


def _add_candidate(candidates: dict[str, dict[str, str]], name: str, version: Any, source: str) -> None:
    clean_name = str(name or "").strip()
    clean_version = _candidate_version(version) if not isinstance(version, str) else _candidate_version(version)
    if not clean_name or not clean_version:
        return
    current = candidates.get(clean_name)
    if not current or _newer_version(clean_version, current["version"]) == clean_version:
        candidates[clean_name] = {"version": clean_version, "source": source}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _collect_package_json(project_path: Path, candidates: dict[str, dict[str, str]]) -> None:
    data = _load_json(project_path / "package.json")
    for section in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "resolutions",
        "overrides",
    ):
        values = data.get(section)
        if not isinstance(values, dict):
            continue
        for name, spec in values.items():
            if isinstance(spec, dict):
                spec = spec.get("version") or spec.get("resolved") or ""
            _add_candidate(candidates, name, spec, f"package.json:{section}")


def _collect_package_lock(project_path: Path, candidates: dict[str, dict[str, str]]) -> None:
    for filename in ("package-lock.json", "npm-shrinkwrap.json"):
        data = _load_json(project_path / filename)
        if not data:
            continue

        packages = data.get("packages")
        if isinstance(packages, dict):
            for package_path, item in packages.items():
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                if not name and isinstance(package_path, str) and package_path.startswith("node_modules/"):
                    name = package_path.rsplit("node_modules/", 1)[-1]
                _add_candidate(candidates, str(name or ""), item.get("version"), filename)

        def visit_dependencies(deps: Any) -> None:
            if not isinstance(deps, dict):
                return
            for name, item in deps.items():
                if not isinstance(item, dict):
                    continue
                _add_candidate(candidates, name, item.get("version"), filename)
                visit_dependencies(item.get("dependencies"))

        visit_dependencies(data.get("dependencies"))


def _yarn_package_name(entry: str) -> str:
    first = entry.split(",", 1)[0].strip().strip('"')
    if first.startswith("@"):
        parts = first.split("@")
        return "@".join(parts[:2]) if len(parts) >= 2 else first
    return first.split("@", 1)[0]


def _collect_yarn_lock(project_path: Path, candidates: dict[str, dict[str, str]]) -> None:
    path = project_path / "yarn.lock"
    if not path.is_file():
        return
    current_names: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for line in lines:
        entry_match = YARN_ENTRY_RE.match(line)
        if entry_match and not line.startswith(" "):
            current_names = [
                _yarn_package_name(part)
                for part in entry_match.group(1).split(",")
                if _yarn_package_name(part)
            ]
            continue
        version_match = YARN_VERSION_RE.match(line)
        if version_match:
            for name in current_names:
                _add_candidate(candidates, name, version_match.group(1), "yarn.lock")


def _collect_pubspec_lock(project_path: Path, candidates: dict[str, dict[str, str]]) -> None:
    path = project_path / "pubspec.lock"
    if not path.is_file():
        return
    current_name: str | None = None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for line in lines:
        name_match = PUBSPEC_NAME_RE.match(line)
        if name_match:
            current_name = name_match.group(1)
            continue
        version_match = PUBSPEC_VERSION_RE.match(line)
        if current_name and version_match:
            _add_candidate(candidates, current_name, version_match.group(1), "pubspec.lock")


def _collect_candidates(project: Project) -> dict[str, dict[str, str]]:
    candidates: dict[str, dict[str, str]] = {}
    if project.kind == "node":
        _collect_package_json(project.path, candidates)
        _collect_package_lock(project.path, candidates)
        _collect_yarn_lock(project.path, candidates)
    elif project.kind == "flutter":
        _collect_pubspec_lock(project.path, candidates)
    return candidates


def _component_name(component: dict[str, Any]) -> str:
    name = str(component.get("name") or "").strip()
    group = str(component.get("group") or "").strip()
    if group.startswith("@") and name and not name.startswith("@"):
        return f"{group}/{name}"
    return name


def _append_property(component: dict[str, Any], name: str, value: str) -> None:
    props = component.setdefault("properties", [])
    if isinstance(props, list):
        props.append({"name": name, "value": value})


def reconcile_sbom_versions(project: Project, sbom_path: Path, log_path: Path) -> dict[str, Any]:
    candidates = _collect_candidates(project)
    stats: dict[str, Any] = {
        "candidate_packages": len(candidates),
        "updated_components": 0,
        "updates": [],
    }
    if not candidates or not sbom_path.is_file():
        return stats

    try:
        data = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return stats
    if not isinstance(data, dict):
        return stats

    for component in data.get("components") or []:
        if not isinstance(component, dict):
            continue
        name = _component_name(component)
        candidate = candidates.get(name)
        if not candidate:
            continue
        old_version = str(component.get("version") or "").strip()
        new_version = candidate["version"]
        if not old_version or _newer_version(new_version, old_version) == new_version and new_version != old_version:
            component["version"] = new_version
            _append_property(component, "autoscan:version-reconciled-from", old_version or "(empty)")
            _append_property(component, "autoscan:version-reconciled-source", candidate["source"])
            stats["updated_components"] += 1
            if len(stats["updates"]) < 200:
                stats["updates"].append({
                    "package": name,
                    "from": old_version or "(empty)",
                    "to": new_version,
                    "source": candidate["source"],
                })

    if stats["updated_components"]:
        sbom_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    ensure_dir(log_path.parent)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write("\n[version-reconcile]\n")
        fh.write(f"Candidate packages: {stats['candidate_packages']}\n")
        fh.write(f"Updated components: {stats['updated_components']}\n")
        for item in stats["updates"][:50]:
            fh.write(f"- {item['package']}: {item['from']} -> {item['to']} ({item['source']})\n")
        if len(stats["updates"]) > 50:
            fh.write(f"... {len(stats['updates']) - 50} more updates omitted\n")

    return stats
