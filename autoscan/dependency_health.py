from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import Project


LOCK_MISSING_ECOSYSTEMS = {"node", "flutter", "php", "ruby"}


def analyze_dependency_health(project: Project) -> dict[str, Any]:
    checks = {
        "node": _check_node,
        "flutter": _check_flutter,
        "php": _check_php,
        "ruby": _check_ruby,
        "python": _check_python,
        "maven": _check_build_based,
        "gradle": _check_build_based,
        "dotnet": _check_build_based,
        "go": _check_go,
    }
    checker = checks.get(project.kind, _check_unknown)
    health = checker(project.path, project.kind)
    health.setdefault("kind", project.kind)
    health.setdefault("manifest_files", [])
    health.setdefault("lock_files", [])
    health.setdefault("issues", [])
    health["status"] = _summary_status(health["issues"])
    health["ok"] = health["status"] == "DEPENDENCY_HEALTH_OK"
    return health


def _summary_status(issues: list[dict[str, Any]]) -> str:
    if not issues:
        return "DEPENDENCY_HEALTH_OK"
    for code in (
        "BUILD_FILE_MISSING",
        "MANIFEST_LOCK_MISMATCH",
        "LOCK_DEPENDENCY_MISSING",
        "LOCK_FILE_MISSING",
        "UNPINNED_DEPENDENCY",
        "UNSUPPORTED_LOCK_CHECK",
    ):
        if any(issue.get("code") == code for issue in issues):
            return code
    return str(issues[0].get("code") or "DEPENDENCY_HEALTH_WARN")


def _issue(
    code: str,
    message: str,
    *,
    severity: str = "WARN",
    file: str = "",
    dependency: str = "",
    declared: str = "",
    resolved: str = "",
    lock_file: str = "",
) -> dict[str, str]:
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "file": file,
        "dependency": dependency,
        "declared": declared,
        "resolved": resolved,
        "lock_file": lock_file,
    }


def _read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _clean_version_spec(spec: Any) -> str:
    text = str(spec or "").strip().strip("\"'")
    if not text or text in {"*", "x", "X"}:
        return ""
    if any(token in text for token in ("||", " - ", "file:", "git+", "http:", "https:", "workspace:", "link:", "path:")):
        return ""
    if "," in text or " " in text:
        return ""
    text = text.removeprefix("v")
    match = re.match(r"^[~^=<>]*(\d+(?:\.\d+)*(?:[-+][0-9A-Za-z_.-]+)?)$", text)
    return match.group(1) if match else ""


def _version_tuple(version: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", version.split("-", 1)[0].split("+", 1)[0])
    return tuple(int(number) for number in numbers[:4]) if numbers else (0,)


def _version_satisfies(spec: Any, resolved: str) -> bool | None:
    minimum = _clean_version_spec(spec)
    if not minimum or not resolved:
        return None
    return _version_tuple(resolved) >= _version_tuple(minimum)


def _direct_deps_from_json(data: dict[str, Any], sections: tuple[str, ...]) -> dict[str, str]:
    deps: dict[str, str] = {}
    for section in sections:
        values = data.get(section)
        if not isinstance(values, dict):
            continue
        for name, spec in values.items():
            if isinstance(spec, str) and name:
                deps[str(name)] = spec
    return deps


def _check_node(path: Path, kind: str) -> dict[str, Any]:
    manifest = path / "package.json"
    lock_paths = [
        path / "package-lock.json",
        path / "npm-shrinkwrap.json",
        path / "yarn.lock",
        path / "pnpm-lock.yaml",
        path / "bun.lock",
        path / "bun.lockb",
    ]
    existing_locks = [item for item in lock_paths if item.is_file()]
    issues: list[dict[str, str]] = []
    deps: dict[str, str] = {}
    resolved: dict[str, tuple[str, str]] = {}

    if not manifest.is_file():
        issues.append(_issue("BUILD_FILE_MISSING", "Node marker found but package.json is missing.", severity="ERROR"))
    else:
        data = _read_json(manifest)
        deps = _direct_deps_from_json(
            data,
            ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"),
        )

    if not existing_locks:
        issues.append(_issue(
            "LOCK_FILE_MISSING",
            "package.json exists but no package-lock.json/yarn.lock/pnpm-lock.yaml/bun.lock was found. Exact transitive versions may be stale or incomplete.",
            file="package.json",
        ))
    if len(existing_locks) > 1:
        issues.append(_issue(
            "MULTIPLE_LOCK_FILES",
            "Multiple Node lock files were found. The SBOM generator may choose one resolver while another lock file is stale.",
            file=", ".join(item.name for item in existing_locks),
        ))

    for lock in existing_locks:
        if lock.name in {"package-lock.json", "npm-shrinkwrap.json"}:
            resolved.update(_node_package_lock_versions(lock))
        elif lock.name == "yarn.lock":
            resolved.update(_yarn_lock_versions(lock))
        elif lock.name.startswith("pnpm-lock"):
            resolved.update(_pnpm_lock_versions(lock))

    issues.extend(_compare_manifest_to_lock(deps, resolved, "package.json"))
    return _health(kind, [manifest], existing_locks, deps, resolved, issues)


def _node_package_lock_versions(path: Path) -> dict[str, tuple[str, str]]:
    data = _read_json(path)
    versions: dict[str, tuple[str, str]] = {}
    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, item in packages.items():
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            if not name and isinstance(package_path, str) and "node_modules/" in package_path:
                name = package_path.rsplit("node_modules/", 1)[-1]
            version = str(item.get("version") or "")
            if name and version:
                versions[name] = (version, path.name)
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        _collect_package_lock_v1(dependencies, versions, path.name)
    return versions


def _collect_package_lock_v1(items: dict[str, Any], versions: dict[str, tuple[str, str]], lock_name: str) -> None:
    for name, item in items.items():
        if not isinstance(item, dict):
            continue
        version = str(item.get("version") or "")
        if name and version:
            versions[str(name)] = (version, lock_name)
        nested = item.get("dependencies")
        if isinstance(nested, dict):
            _collect_package_lock_v1(nested, versions, lock_name)


def _yarn_lock_versions(path: Path) -> dict[str, tuple[str, str]]:
    versions: dict[str, tuple[str, str]] = {}
    current_names: list[str] = []
    for line in _read_text(path).splitlines():
        if line and not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            current_names = [_yarn_entry_name(part.strip()) for part in line.rstrip(":").split(",")]
            current_names = [name for name in current_names if name]
            continue
        match = re.match(r"\s+version\s+\"?([^\"\s]+)\"?", line)
        if match:
            for name in current_names:
                versions[name] = (match.group(1), path.name)
    return versions


def _yarn_entry_name(entry: str) -> str:
    entry = entry.strip().strip("\"'")
    if entry.startswith("@"):
        parts = entry.split("@")
        return "@".join(parts[:2]) if len(parts) >= 3 else ""
    return entry.split("@", 1)[0]


def _pnpm_lock_versions(path: Path) -> dict[str, tuple[str, str]]:
    versions: dict[str, tuple[str, str]] = {}
    text = _read_text(path)
    for match in re.finditer(r"^\s{2,}([@A-Za-z0-9_.-][^:\s]*):\n(?:\s{4,}specifier:\s*([^\n]+)\n)?\s{4,}version:\s*([^\s(]+)", text, re.MULTILINE):
        name = match.group(1).strip("'\"")
        versions[name] = (match.group(3).strip("'\""), path.name)
    for match in re.finditer(r"^\s{2,}/?((?:@[^/]+/)?[^@\s:]+)@([^:\s]+):", text, re.MULTILINE):
        versions.setdefault(match.group(1), (match.group(2), path.name))
    return versions


def _check_flutter(path: Path, kind: str) -> dict[str, Any]:
    manifest = path / "pubspec.yaml"
    lock = path / "pubspec.lock"
    issues: list[dict[str, str]] = []
    deps = _pubspec_deps(manifest)
    locks = [lock] if lock.is_file() else []
    if not lock.is_file():
        issues.append(_issue(
            "LOCK_FILE_MISSING",
            "pubspec.yaml exists but pubspec.lock is missing. Flutter scan may not reflect exact resolved package versions.",
            file="pubspec.yaml",
        ))
    resolved = _pubspec_lock_versions(lock) if lock.is_file() else {}
    issues.extend(_compare_manifest_to_lock(deps, resolved, "pubspec.yaml"))
    return _health(kind, [manifest], locks, deps, resolved, issues)


def _pubspec_deps(path: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    current_section = ""
    for line in _read_text(path).splitlines():
        raw = line.split("#", 1)[0].rstrip()
        if not raw:
            continue
        section = raw.strip().rstrip(":")
        if not line.startswith((" ", "\t")):
            current_section = section if section in {"dependencies", "dev_dependencies"} else ""
            continue
        if current_section and re.match(r"^\s{2,}[A-Za-z0-9_.-]+:", raw):
            name, value = raw.strip().split(":", 1)
            spec = value.strip().strip("\"'")
            if spec and spec not in {"flutter", "sdk"} and not spec.startswith(("{", "[")):
                deps[name] = spec
    return deps


def _pubspec_lock_versions(path: Path) -> dict[str, tuple[str, str]]:
    versions: dict[str, tuple[str, str]] = {}
    current = ""
    for line in _read_text(path).splitlines():
        match_name = re.match(r"^\s{2}([A-Za-z0-9_.-]+):\s*$", line)
        if match_name:
            current = match_name.group(1)
            continue
        match_version = re.match(r"^\s{4}version:\s+\"?([^\"\s]+)\"?", line)
        if current and match_version:
            versions[current] = (match_version.group(1), path.name)
    return versions


def _check_php(path: Path, kind: str) -> dict[str, Any]:
    manifest = path / "composer.json"
    lock = path / "composer.lock"
    data = _read_json(manifest)
    deps = _direct_deps_from_json(data, ("require", "require-dev"))
    deps = {name: spec for name, spec in deps.items() if not name.startswith(("php", "ext-"))}
    issues: list[dict[str, str]] = []
    locks = [lock] if lock.is_file() else []
    if not lock.is_file():
        issues.append(_issue("LOCK_FILE_MISSING", "composer.json exists but composer.lock is missing.", file="composer.json"))
    resolved = _composer_lock_versions(lock) if lock.is_file() else {}
    issues.extend(_compare_manifest_to_lock(deps, resolved, "composer.json"))
    return _health(kind, [manifest], locks, deps, resolved, issues)


def _composer_lock_versions(path: Path) -> dict[str, tuple[str, str]]:
    data = _read_json(path)
    versions: dict[str, tuple[str, str]] = {}
    for section in ("packages", "packages-dev"):
        for item in data.get(section) or []:
            if isinstance(item, dict) and item.get("name") and item.get("version"):
                versions[str(item["name"])] = (str(item["version"]).lstrip("v"), path.name)
    return versions


def _check_ruby(path: Path, kind: str) -> dict[str, Any]:
    manifest = path / "Gemfile"
    lock = path / "Gemfile.lock"
    deps = _gemfile_deps(manifest)
    issues: list[dict[str, str]] = []
    locks = [lock] if lock.is_file() else []
    if not lock.is_file():
        issues.append(_issue("LOCK_FILE_MISSING", "Gemfile exists but Gemfile.lock is missing.", file="Gemfile"))
    resolved = _gemfile_lock_versions(lock) if lock.is_file() else {}
    issues.extend(_compare_manifest_to_lock(deps, resolved, "Gemfile"))
    return _health(kind, [manifest], locks, deps, resolved, issues)


def _gemfile_deps(path: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    for line in _read_text(path).splitlines():
        match = re.match(r"\s*gem\s+['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?", line)
        if match and match.group(2):
            deps[match.group(1)] = match.group(2)
    return deps


def _gemfile_lock_versions(path: Path) -> dict[str, tuple[str, str]]:
    versions: dict[str, tuple[str, str]] = {}
    for line in _read_text(path).splitlines():
        match = re.match(r"\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)", line)
        if match:
            versions[match.group(1)] = (match.group(2).split(",")[0], path.name)
    return versions


def _check_python(path: Path, kind: str) -> dict[str, Any]:
    manifest_files = [item for item in (path / "requirements.txt", path / "pyproject.toml", path / "Pipfile") if item.is_file()]
    lock_files = [item for item in (path / "poetry.lock", path / "Pipfile.lock") if item.is_file()]
    issues: list[dict[str, str]] = []
    deps: dict[str, str] = {}
    resolved: dict[str, tuple[str, str]] = {}

    requirements = path / "requirements.txt"
    if requirements.is_file():
        deps.update(_requirements_deps(requirements))
        for name, spec in deps.items():
            if not spec.startswith("=="):
                issues.append(_issue(
                    "UNPINNED_DEPENDENCY",
                    f"requirements.txt dependency {name} is not pinned with ==; resolved scan version may vary.",
                    file="requirements.txt",
                    dependency=name,
                    declared=spec,
                ))
    if (path / "pyproject.toml").is_file() and not (path / "poetry.lock").is_file():
        issues.append(_issue("LOCK_FILE_MISSING", "pyproject.toml exists but poetry.lock is missing.", file="pyproject.toml"))
    if (path / "Pipfile").is_file() and not (path / "Pipfile.lock").is_file():
        issues.append(_issue("LOCK_FILE_MISSING", "Pipfile exists but Pipfile.lock is missing.", file="Pipfile"))
    if (path / "Pipfile.lock").is_file():
        resolved.update(_pipfile_lock_versions(path / "Pipfile.lock"))
    return _health(kind, manifest_files, lock_files, deps, resolved, issues)


def _requirements_deps(path: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    for line in _read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(("-", "git+", "http:", "https:")):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)\s*([=<>!~].+)?", line)
        if match:
            deps[match.group(1)] = (match.group(2) or "").strip()
    return deps


def _pipfile_lock_versions(path: Path) -> dict[str, tuple[str, str]]:
    data = _read_json(path)
    versions: dict[str, tuple[str, str]] = {}
    for section in ("default", "develop"):
        values = data.get(section)
        if not isinstance(values, dict):
            continue
        for name, item in values.items():
            if isinstance(item, dict) and item.get("version"):
                versions[str(name)] = (str(item["version"]).lstrip("="), path.name)
    return versions


def _check_go(path: Path, kind: str) -> dict[str, Any]:
    manifest = path / "go.mod"
    lock = path / "go.sum"
    issues: list[dict[str, str]] = []
    locks = [lock] if lock.is_file() else []
    if not lock.is_file():
        issues.append(_issue("LOCK_FILE_MISSING", "go.mod exists but go.sum is missing.", file="go.mod"))
    return _health(kind, [manifest], locks, {}, {}, issues)


def _check_build_based(path: Path, kind: str) -> dict[str, Any]:
    manifests = {
        "maven": [path / "pom.xml"],
        "gradle": [path / "build.gradle", path / "build.gradle.kts", path / "settings.gradle", path / "settings.gradle.kts"],
        "dotnet": list(path.glob("*.sln")) + list(path.glob("*.csproj")),
    }.get(kind, [])
    manifests = [item for item in manifests if item.is_file()]
    issues: list[dict[str, str]] = []
    if not manifests:
        issues.append(_issue("BUILD_FILE_MISSING", f"{kind} project was detected but no build file was found.", severity="ERROR"))
    if kind == "dotnet" and not (path / "packages.lock.json").is_file():
        issues.append(_issue("LOCK_FILE_MISSING", ".NET project has no packages.lock.json; resolved transitive versions may vary.", file="*.csproj"))
    return _health(kind, manifests, [path / "packages.lock.json"] if (path / "packages.lock.json").is_file() else [], {}, {}, issues)


def _check_unknown(path: Path, kind: str) -> dict[str, Any]:
    issue = _issue(
        "BUILD_FILE_MISSING",
        "No recognized build/dependency manifest was found, so exact ecosystem dependency resolution cannot be verified.",
        severity="ERROR",
    )
    return _health(kind, [], [], {}, {}, [issue])


def _compare_manifest_to_lock(
    deps: dict[str, str],
    resolved: dict[str, tuple[str, str]],
    manifest_name: str,
) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    for name, spec in sorted(deps.items()):
        if not resolved:
            continue
        locked = resolved.get(name)
        if not locked:
            issues.append(_issue(
                "LOCK_DEPENDENCY_MISSING",
                f"{manifest_name} declares {name}, but no matching resolved version was found in the lock file.",
                file=manifest_name,
                dependency=name,
                declared=spec,
            ))
            continue
        locked_version, lock_file = locked
        satisfied = _version_satisfies(spec, locked_version)
        if satisfied is False:
            issues.append(_issue(
                "MANIFEST_LOCK_MISMATCH",
                f"{manifest_name} declares {name} {spec}, but {lock_file} resolves {locked_version}. Scan follows the resolved lock/SBOM version.",
                file=manifest_name,
                dependency=name,
                declared=spec,
                resolved=locked_version,
                lock_file=lock_file,
            ))
    return issues


def _health(
    kind: str,
    manifests: list[Path],
    locks: list[Path],
    declared: dict[str, str],
    resolved: dict[str, tuple[str, str]],
    issues: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "kind": kind,
        "manifest_files": [item.name for item in manifests if item.is_file()],
        "lock_files": [item.name for item in locks if item.is_file()],
        "declared_direct_dependencies": len(declared),
        "resolved_lock_dependencies": len(resolved),
        "issues": issues,
    }
