from __future__ import annotations

import html
import json
import re
import time
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .license_rules import KNOWN_SPDX_IDS, normalize_license_name
from .utils import ensure_dir

FetchLicense = Callable[[str, str], tuple[str, str] | None]

_PACKAGE_RE = re.compile(r"^  ([A-Za-z0-9_\-.]+):\s*$")
_FIELD_RE = re.compile(r"^    ([A-Za-z0-9_\-.]+):\s*(.*)$")
_SPDX_RE = re.compile(r"\b(?:Apache-2\.0|MIT|BSD-3-Clause|BSD-2-Clause|ISC|Zlib|EPL-2\.0|EPL-1\.0|MPL-2\.0|MPL-1\.1|LGPL-2\.1-or-later|LGPL-2\.1-only|LGPL-3\.0-only|GPL-2\.0-only|GPL-3\.0-only|AGPL-3\.0-only|CC0-1\.0|Unlicense|UPL-1\.0)\b")


def read_pubspec_lock_packages(lock_path: Path) -> dict[str, str]:
    if not lock_path.is_file():
        return {}

    packages: dict[str, dict[str, str]] = {}
    current: str | None = None
    in_packages = False

    for raw_line in lock_path.read_text(encoding="utf-8").splitlines():
        if raw_line.strip() == "packages:":
            in_packages = True
            continue
        if not in_packages:
            continue
        if raw_line and not raw_line.startswith(" "):
            break
        package_match = _PACKAGE_RE.match(raw_line)
        if package_match:
            current = package_match.group(1)
            packages[current] = {}
            continue
        if not current:
            continue
        field_match = _FIELD_RE.match(raw_line)
        if field_match:
            key, value = field_match.groups()
            packages[current][key] = _clean_yaml_scalar(value)

    return {
        name: fields["version"]
        for name, fields in packages.items()
        if fields.get("source") == "hosted" and fields.get("version")
    }


def enrich_flutter_licenses(
    project_path: Path,
    sbom_path: Path,
    cache_path: Path,
    log_path: Path,
    *,
    fetcher: FetchLicense | None = None,
) -> dict[str, int]:
    stats = {
        "packages": 0,
        "components": 0,
        "updated": 0,
        "skipped_existing": 0,
        "missing_component": 0,
        "not_found": 0,
        "errors": 0,
    }
    lock_packages = read_pubspec_lock_packages(project_path / "pubspec.lock")
    stats["packages"] = len(lock_packages)
    if not lock_packages or not sbom_path.is_file():
        _write_log(log_path, [f"packages={stats['packages']} updated=0"])
        return stats

    data = json.loads(sbom_path.read_text(encoding="utf-8"))
    components = data.get("components") or []
    if not isinstance(components, list):
        _write_log(log_path, ["components field is not a list"])
        return stats
    stats["components"] = len(components)

    cache = _load_cache(cache_path)
    fetch = fetcher or fetch_pubdev_license
    log_lines: list[str] = []

    for package, version in lock_packages.items():
        component = _find_component(components, package, version)
        if component is None:
            stats["missing_component"] += 1
            log_lines.append(f"MISS component package={package} version={version}")
            continue
        if _has_declared_license(component):
            stats["skipped_existing"] += 1
            log_lines.append(f"SKIP existing package={package} version={version}")
            continue

        key = f"{package}@{version}"
        cached = cache.get(key)
        if cached:
            license_id = str(cached.get("license") or "")
            source = str(cached.get("source") or "cache")
        else:
            try:
                fetched = fetch(package, version)
            except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
                stats["errors"] += 1
                log_lines.append(f"ERROR package={package} version={version} error={exc}")
                continue
            if not fetched:
                stats["not_found"] += 1
                log_lines.append(f"UNKNOWN package={package} version={version}")
                continue
            license_id, source = fetched
            cache[key] = {"license": license_id, "source": source, "cached_at": int(time.time())}

        if not license_id or license_id.startswith("LicenseRef-"):
            stats["not_found"] += 1
            log_lines.append(f"UNKNOWN package={package} version={version} source={source}")
            continue

        component["licenses"] = [{"license": {"id": license_id}}]
        stats["updated"] += 1
        log_lines.append(f"UPDATE package={package} version={version} license={license_id} source={source}")

    if stats["updated"]:
        sbom_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    _save_cache(cache_path, cache)
    _write_log(log_path, log_lines + [json.dumps(stats, sort_keys=True)])
    return stats


def fetch_pubdev_license(package: str, version: str, *, timeout: float = 10.0) -> tuple[str, str] | None:
    del version
    safe_package = quote(package, safe="")
    urls = [
        f"https://pub.dev/packages/{safe_package}/license",
        f"https://pub.dev/packages/{safe_package}",
    ]
    for url in urls:
        request = Request(url, headers={"User-Agent": "autoscan-license-enricher/1.0"})
        try:
            with urlopen(request, timeout=timeout) as response:
                body = response.read(512_000).decode("utf-8", errors="replace")
        except (HTTPError, URLError, TimeoutError):
            continue
        license_id = _extract_license_id(body)
        if license_id:
            return license_id, url
    return None


def _clean_yaml_scalar(value: str) -> str:
    value = value.strip()
    if value in {"", "|", ">"}:
        return ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _extract_license_id(body: str) -> str | None:
    text = html.unescape(re.sub(r"<[^>]+>", " ", body))
    spdx_match = _SPDX_RE.search(text)
    if spdx_match:
        return spdx_match.group(0)
    normalized = normalize_license_name(" ".join(text.split())[:4000])
    if normalized in KNOWN_SPDX_IDS:
        return normalized
    return None


def _find_component(components: list[object], package: str, version: str) -> dict | None:
    for component in components:
        if not isinstance(component, dict):
            continue
        name = str(component.get("name") or "")
        component_version = str(component.get("version") or "")
        purl = str(component.get("purl") or "")
        if name == package and (not component_version or component_version == version):
            return component
        if f"pkg:pub/{package}@{version}" in purl or f"pkg:pub/{package}" in purl:
            return component
    return None


def _has_declared_license(component: dict) -> bool:
    licenses = component.get("licenses") or []
    return isinstance(licenses, list) and any(isinstance(item, dict) and item for item in licenses)


def _load_cache(cache_path: Path) -> dict[str, dict[str, object]]:
    if not cache_path.is_file():
        return {}
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_cache(cache_path: Path, cache: dict[str, dict[str, object]]) -> None:
    ensure_dir(cache_path.parent)
    cache_path.write_text(json.dumps(cache, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def _write_log(log_path: Path, lines: list[str]) -> None:
    ensure_dir(log_path.parent)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
