from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote


UNKNOWN_PACKAGE = "(unknown)"
LOOSE_FILE_PACKAGE = "Loose File License(s)"


def canonical_pkg_key(value: Any) -> str:
    """Return a canonical, comparable key for a package name.

    The same artifact can be referenced in SBOMs and Trivy reports in several
    equivalent spellings:

      * ``ch.qos.logback/logback-classic``  (group + slash + name)
      * ``ch.qos.logback:logback-classic``  (Maven coordinate, colon separator)
      * ``logback-classic``                 (name only, no group)

    All three refer to the same artifact and must be merged into a single
    report row, otherwise the consolidated report shows duplicates. This helper
    normalises the spelling so callers can use the result as a deduplication
    key. Falls back to the lower-cased input when no recognisable shape is
    found. The unknown / empty sentinels are kept verbatim so they still group
    together without being silently collapsed onto a real package name.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if text in (UNKNOWN_PACKAGE, LOOSE_FILE_PACKAGE):
        return text.lower()

    lowered = text.lower()
    # Maven coordinate: group:artifact[:version] — use only group:artifact.
    # Skip the leading "pkg:" scheme (PURL) and anything that contains "/" or
    # a URL scheme; those are handled by the slash branch below.
    if (
        ":" in lowered
        and "/" not in lowered
        and not lowered.startswith(("pkg:", "http:", "https:", "file:", "jar:", "cpe:"))
    ):
        parts = lowered.split(":")
        if len(parts) >= 2 and parts[0] and parts[1]:
            # Drop a trailing version (anything after the 2nd colon) so
            # "group:artifact:1.2.3" still normalises to "group:artifact".
            if len(parts) == 2:
                return f"{parts[0]}/{parts[1]}"
            return f"{parts[0]}/{parts[1]}"
    # group/name spelling: convert to lower-case for case-insensitive match.
    if "/" in lowered:
        return lowered
    return lowered


_MISSING_VALUES = {
    "",
    "-",
    "none",
    "null",
    "unknown",
    "(unknown)",
    "<unknown>",
}
_GENERIC_PATH_PARTS = {
    ".",
    "..",
    "license",
    "licenses",
    "licence",
    "licences",
    "third-party",
    "third_party",
}


@dataclass(frozen=True)
class PackageNameResolution:
    name: str
    source: str
    raw_missing: bool


def usable_package_name(value: Any) -> str:
    text = str(value or "").strip()
    if text.lower() in _MISSING_VALUES:
        return ""
    return text


def resolve_package_name(
    item: dict[str, Any],
    *,
    result_target: str = "",
    result_class: str = "",
) -> PackageNameResolution:
    component_name = usable_package_name(item.get("name"))
    component_group = usable_package_name(item.get("group"))
    if component_group and component_name and not component_name.startswith(component_group):
        return PackageNameResolution(f"{component_group}/{component_name}", "component-group-name", raw_missing=False)
    if component_name:
        return PackageNameResolution(component_name, "component-name", raw_missing=False)

    raw_name = usable_package_name(item.get("PkgName") or item.get("Package"))
    if raw_name:
        return PackageNameResolution(raw_name, "explicit", raw_missing=False)

    candidates: list[tuple[str, str]] = []
    for field in ("PURL", "PkgPURL", "purl"):
        candidates.append((field, _name_from_purl(item.get(field))))

    identifier = item.get("PkgIdentifier")
    if isinstance(identifier, dict):
        candidates.append(("PkgIdentifier.PURL", _name_from_purl(identifier.get("PURL"))))
        candidates.append(("PkgIdentifier.UID", _name_from_pkg_id(identifier.get("UID"))))

    for field in ("PkgID", "ID", "ComponentID", "PackageID", "bom-ref", "bomRef", "BOMRef"):
        candidates.append((field, _name_from_pkg_id(item.get(field))))

    for field in ("PkgPath", "FilePath"):
        candidates.append((field, _name_from_path(item.get(field))))

    candidates.append(("Target", _name_from_path(result_target)))
    candidates.append(("Target", _name_from_purl(result_target)))

    for source, name in candidates:
        clean = usable_package_name(name)
        if clean and clean.lower() not in _GENERIC_PATH_PARTS:
            return PackageNameResolution(clean, source, raw_missing=True)

    target = str(result_target or "").strip()
    if result_class == "license-file" or target == LOOSE_FILE_PACKAGE:
        return PackageNameResolution(
            target if target and target != "-" else LOOSE_FILE_PACKAGE,
            "license-file-target",
            raw_missing=True,
        )

    return PackageNameResolution(UNKNOWN_PACKAGE, "unresolved", raw_missing=True)


def annotate_report_package_names(data: dict[str, Any]) -> dict[str, Any]:
    stats = {
        "vulnerabilities": _empty_stats(),
        "licenses": _empty_stats(),
    }

    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "")
        result_class = str(result.get("Class") or "")
        _annotate_items(
            result.get("Vulnerabilities") or [],
            stats["vulnerabilities"],
            target,
            result_class,
        )
        _annotate_items(
            result.get("Licenses") or [],
            stats["licenses"],
            target,
            result_class,
        )

    metadata = data.setdefault("Metadata", {})
    if isinstance(metadata, dict):
        autoscan = metadata.setdefault("AutoScan", {})
        if isinstance(autoscan, dict):
            autoscan["package_name_resolution"] = stats
    return stats


def _empty_stats() -> dict[str, Any]:
    return {
        "total": 0,
        "raw_missing": 0,
        "resolved_from_fallback": 0,
        "unresolved": 0,
        "samples": [],
    }


def _annotate_items(
    items: list[Any],
    stats: dict[str, Any],
    target: str,
    result_class: str,
) -> None:
    for item in items:
        if not isinstance(item, dict):
            continue
        stats["total"] += 1
        resolution = resolve_package_name(
            item,
            result_target=target,
            result_class=result_class,
        )
        if resolution.raw_missing:
            stats["raw_missing"] += 1
            if resolution.name == UNKNOWN_PACKAGE:
                stats["unresolved"] += 1
            else:
                stats["resolved_from_fallback"] += 1
            _add_sample(stats, item, target, result_class, resolution)

        if not usable_package_name(item.get("PkgName")):
            item["PkgName"] = resolution.name
        item["_AutoScanPkgNameSource"] = resolution.source


def _add_sample(
    stats: dict[str, Any],
    item: dict[str, Any],
    target: str,
    result_class: str,
    resolution: PackageNameResolution,
) -> None:
    samples = stats["samples"]
    if len(samples) >= 20:
        return
    fields = {}
    for key in (
        "PkgName",
        "Package",
        "PkgID",
        "PURL",
        "PkgPURL",
        "PkgPath",
        "FilePath",
        "VulnerabilityID",
        "Name",
    ):
        if item.get(key):
            fields[key] = item.get(key)
    identifier = item.get("PkgIdentifier")
    if isinstance(identifier, dict):
        fields["PkgIdentifier"] = {
            key: identifier.get(key)
            for key in ("PURL", "UID")
            if identifier.get(key)
        }
    samples.append({
        "resolved": resolution.name,
        "source": resolution.source,
        "target": target,
        "class": result_class,
        "fields": fields,
    })


def _name_from_purl(value: Any) -> str:
    text = str(value or "").strip()
    if not text.startswith("pkg:"):
        return ""

    body = text[4:].split("?", 1)[0].split("#", 1)[0]
    if "/" not in body:
        return ""
    _, path = body.split("/", 1)
    if "@" in path:
        name_part, _, version = path.rpartition("@")
        if name_part and version:
            path = name_part
    parts = [unquote(part) for part in path.split("/") if part]
    if not parts:
        return ""
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return parts[-1]


def _name_from_pkg_id(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    purl_name = _name_from_purl(text)
    if purl_name:
        return purl_name
    if "@" in text:
        name_part, _, version = text.rpartition("@")
        if name_part and version[:1].isdigit():
            return name_part
    if (
        text.count(":") >= 2
        and not text.lower().startswith(("cpe:", "http:", "https:", "file:", "jar:"))
    ):
        parts = [part for part in text.split(":") if part]
        if len(parts) >= 3 and usable_package_name(parts[0]) and usable_package_name(parts[1]):
            return f"{parts[0]}/{parts[1]}"
    if " " in text:
        first = text.split(" ", 1)[0]
        if usable_package_name(first):
            return first
    return ""


def _name_from_path(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    normalized = text.replace("\\", "/")
    if normalized == LOOSE_FILE_PACKAGE:
        return LOOSE_FILE_PACKAGE

    parts = [unquote(part) for part in PurePosixPath(normalized).parts if part not in ("", "/")]
    if not parts:
        return ""

    lowered = [part.lower() for part in parts]
    if "node_modules" in lowered:
        idx = len(lowered) - 1 - lowered[::-1].index("node_modules")
        if idx + 1 < len(parts):
            first = parts[idx + 1]
            if first.startswith("@") and idx + 2 < len(parts):
                return f"{first}/{parts[idx + 2]}"
            return first

    if lowered[0] in {"licenses", "licences"}:
        return LOOSE_FILE_PACKAGE

    for marker in ("packages", "apps", "libs", "modules"):
        if marker in lowered:
            idx = lowered.index(marker)
            if idx + 1 < len(parts):
                candidate = parts[idx + 1]
                if usable_package_name(candidate):
                    return candidate

    file_name = parts[-1]
    stem = file_name.rsplit(".", 1)[0]
    if len(parts) >= 2 and stem.lower() in {"license", "licence", "copying", "notice"}:
        return parts[-2]
    return ""
