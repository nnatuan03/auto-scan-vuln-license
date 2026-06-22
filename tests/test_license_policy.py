from autoscan.license_inventory import classify_license, licenses_from_sbom
from autoscan.trivy_runner import _dedupe_license_report


def test_classify_known_license_refs():
    assert classify_license("LicenseRef-Public-Domain") == ("LOW", "permissive")
    assert classify_license("LicenseRef-CDDL-GPLv2-CE") == ("MEDIUM", "reciprocal")
    assert classify_license("LicenseRef-Oracle-FUTC") == ("HIGH", "restricted")


def test_license_overrides_and_manifest_filter(tmp_path):
    sbom = tmp_path / "SBOM.cdx.json"
    sbom.write_text(
        """
{
  "components": [
    {"group": "io.swagger.parser.v3", "name": "swagger-parser-v3", "version": "2.1.22"},
    {"group": "com.oracle.database.jdbc", "name": "ojdbc8", "version": "23.3.0.23.09"},
    {"name": "flutter", "version": "0.0.0", "purl": "pkg:pub/flutter@0.0.0"},
    {"name": "pubspec.lock", "type": "file"},
    {"name": "pom.xml", "type": "file"}
  ]
}
""".strip(),
        encoding="utf-8",
    )

    rows = licenses_from_sbom(sbom)
    by_package = {row["PkgName"]: row for row in rows}

    assert by_package["io.swagger.parser.v3/swagger-parser-v3"]["Name"] == "Apache-2.0"
    assert by_package["com.oracle.database.jdbc/ojdbc8"]["Name"] == "LicenseRef-Oracle-FUTC"
    assert by_package["flutter"]["Name"] == "BSD-3-Clause"
    assert "pubspec.lock" not in by_package
    assert "pom.xml" not in by_package


def test_trivy_license_report_applies_policy_and_filters_manifests():
    data = {
        "Results": [{
            "Target": "SBOM.cdx-fix.json",
            "Licenses": [
                {"PkgName": "io.swagger.parser.v3/swagger-parser-v3", "Name": "LicenseRef-No-Declared-License", "Severity": "UNKNOWN"},
                {"PkgName": "aopalliance:aopalliance", "Name": "LicenseRef-Public-Domain", "Severity": "UNKNOWN"},
                {"PkgName": "pubspec.lock", "Name": "LicenseRef-No-Declared-License", "Severity": "UNKNOWN"},
            ],
        }],
    }

    report, stats = _dedupe_license_report(data)
    rows = report["Results"][0]["Licenses"]
    by_package = {row["PkgName"]: row for row in rows}

    assert stats["raw"] == 3
    assert "pubspec.lock" not in by_package
    assert by_package["io.swagger.parser.v3/swagger-parser-v3"]["Name"] == "Apache-2.0"
    assert by_package["aopalliance:aopalliance"]["Severity"] == "LOW"
