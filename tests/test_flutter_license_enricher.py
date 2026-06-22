import json

from autoscan.flutter_license_enricher import enrich_flutter_licenses, read_pubspec_lock_packages


def test_read_pubspec_lock_packages_returns_versions(tmp_path):
    lock_path = tmp_path / "pubspec.lock"
    lock_path.write_text(
        """
packages:
  async:
    dependency: transitive
    description:
      name: async
      url: "https://pub.dev"
    source: hosted
    version: "2.11.0"
  local_pkg:
    dependency: direct main
    description:
      path: ../local_pkg
    source: path
    version: "1.0.0"
""".strip(),
        encoding="utf-8",
    )

    packages = read_pubspec_lock_packages(lock_path)

    assert packages == {"async": "2.11.0"}


def test_enrich_flutter_licenses_adds_missing_pub_license(tmp_path):
    project_path = tmp_path / "app"
    project_path.mkdir()
    (project_path / "pubspec.lock").write_text(
        """
packages:
  async:
    dependency: transitive
    description:
      name: async
      url: "https://pub.dev"
    source: hosted
    version: "2.11.0"
""".strip(),
        encoding="utf-8",
    )
    sbom_path = tmp_path / "SBOM.cdx.json"
    sbom_path.write_text(
        json.dumps({
            "bomFormat": "CycloneDX",
            "components": [{"name": "async", "version": "2.11.0", "purl": "pkg:pub/async@2.11.0"}],
        }),
        encoding="utf-8",
    )

    stats = enrich_flutter_licenses(
        project_path,
        sbom_path,
        tmp_path / "cache.json",
        tmp_path / "pub-license-enrich.log",
        fetcher=lambda package, version: ("MIT", f"https://pub.dev/packages/{package}/license"),
    )

    updated = json.loads(sbom_path.read_text(encoding="utf-8"))
    assert stats["updated"] == 1
    assert updated["components"][0]["licenses"] == [{"license": {"id": "MIT"}}]


def test_enrich_flutter_licenses_does_not_overwrite_existing_license(tmp_path):
    project_path = tmp_path / "app"
    project_path.mkdir()
    (project_path / "pubspec.lock").write_text(
        """
packages:
  async:
    dependency: transitive
    description:
      name: async
      url: "https://pub.dev"
    source: hosted
    version: "2.11.0"
""".strip(),
        encoding="utf-8",
    )
    sbom_path = tmp_path / "SBOM.cdx.json"
    sbom_path.write_text(
        json.dumps({
            "components": [{
                "name": "async",
                "version": "2.11.0",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
            }],
        }),
        encoding="utf-8",
    )

    stats = enrich_flutter_licenses(
        project_path,
        sbom_path,
        tmp_path / "cache.json",
        tmp_path / "pub-license-enrich.log",
        fetcher=lambda package, version: ("MIT", f"https://pub.dev/packages/{package}/license"),
    )

    updated = json.loads(sbom_path.read_text(encoding="utf-8"))
    assert stats["skipped_existing"] == 1
    assert updated["components"][0]["licenses"] == [{"license": {"id": "BSD-3-Clause"}}]
