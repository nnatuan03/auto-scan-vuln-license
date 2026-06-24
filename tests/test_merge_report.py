from autoscan.reporting.merge_report import generate_html, group_licenses, group_vulns


def test_consolidated_excel_export_includes_service_first_sheets(tmp_path):
    services_dir = tmp_path / "scan-results"
    services_dir.mkdir()
    service_a = services_dir / "service-a"
    service_a.mkdir()
    (service_a / "report.json").write_text(
        """
        {
          "Results": [
            {
              "Target": "pom.xml",
              "Class": "lang-pkgs",
              "Vulnerabilities": [
                {
                  "PkgName": "lodash",
                  "InstalledVersion": "4.17.15",
                  "FixedVersion": "4.17.21",
                  "VulnerabilityID": "CVE-2021-23337",
                  "Severity": "HIGH",
                  "Title": "Command injection"
                }
              ],
              "Licenses": [
                {
                  "PkgName": "lodash",
                  "Name": "MIT",
                  "Severity": "LOW",
                  "FilePath": "pkg:npm/lodash@4.17.15"
                }
              ]
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    output_html = tmp_path / "consolidated-report.html"
    generate_html(services_dir, output_html)

    html = output_html.read_text(encoding="utf-8")

    assert "function buildSummarySheet()" in html
    assert "function buildByServiceSheet()" in html
    assert "function buildAffectedInstancesSheet()" in html
    assert "XLSX.utils.book_append_sheet(wb, buildSummarySheet(), 'Summary');" in html
    assert "XLSX.utils.book_append_sheet(wb, buildByServiceSheet(), 'By Service');" in html
    assert "XLSX.utils.book_append_sheet(wb, buildAffectedInstancesSheet(), 'Affected Instances');" in html
    assert "['Service','Finding Type','Severity','Package','Installed','Fixed','CVE','Target','Title']" in html


def test_group_vulns_preserves_service_version_mapping():
    groups = group_vulns([
        {
            "folder": "service-a",
            "pkg": "lodash",
            "version": "4.17.15",
            "fixed": "4.17.21",
            "cve": "CVE-2021-23337",
            "severity": "HIGH",
            "title": "Command injection",
            "url": "https://example.test/cve",
        },
        {
            "folder": "service-b",
            "pkg": "lodash",
            "version": "4.17.19",
            "fixed": "4.17.21",
            "cve": "CVE-2021-23337",
            "severity": "HIGH",
            "title": "Command injection",
            "url": "https://example.test/cve",
        },
        {
            "folder": "service-c",
            "pkg": "lodash",
            "version": "4.17.15",
            "fixed": "4.17.21",
            "cve": "CVE-2021-23337",
            "severity": "HIGH",
            "title": "Command injection",
            "url": "https://example.test/cve",
        },
    ])

    vuln = groups[0]["vulns"][0]

    assert vuln["versions"] == ["4.17.15", "4.17.19"]
    assert vuln["affected_instances"] == [
        {"service": "service-a", "version": "4.17.15", "fixed": "4.17.21"},
        {"service": "service-b", "version": "4.17.19", "fixed": "4.17.21"},
        {"service": "service-c", "version": "4.17.15", "fixed": "4.17.21"},
    ]

def test_group_licenses_drops_no_declared_when_detected_license_exists():
    groups = group_licenses([
        {
            "folder": "svc",
            "pkg": "fake_async",
            "license": "Apache-2.0",
            "severity": "LOW",
            "filepath": "pkg:pub/fake_async@1.0.0",
            "target": "SBOM.cdx-fix.json",
        },
        {
            "folder": "svc",
            "pkg": "fake_async",
            "license": "LicenseRef-No-Declared-License",
            "severity": "UNKNOWN",
            "filepath": "pkg:pub/fake_async@1.0.0",
            "target": "SBOM.cdx-fix.json",
        },
    ])

    assert len(groups) == 1
    assert [row["license"] for row in groups[0]["licenses"]] == ["Apache-2.0"]
    assert groups[0]["severity"] == "LOW"

def test_group_licenses_normalizes_license_ref_severity_before_dedupe():
    groups = group_licenses([
        {
            "folder": "svc",
            "pkg": "javax.activation:javax.activation-api",
            "license": "LicenseRef-CDDL-GPLv2-CE",
            "severity": "HIGH",
            "filepath": "pkg:maven/javax.activation/javax.activation-api@1.2.0",
            "target": "SBOM.cdx-fix.json",
        },
        {
            "folder": "svc",
            "pkg": "javax.activation:javax.activation-api",
            "license": "LicenseRef-CDDL-GPLv2-CE",
            "severity": "UNKNOWN",
            "filepath": "pkg:maven/javax.activation/javax.activation-api@1.2.0",
            "target": "SBOM.cdx-fix.json",
        },
    ])

    assert len(groups) == 1
    assert [(row["license"], row["severity"]) for row in groups[0]["licenses"]] == [
        ("LicenseRef-CDDL-GPLv2-CE", "HIGH")
    ]
    assert groups[0]["severity"] == "HIGH"

def test_group_licenses_classifies_classpath_exception_license_ref_as_high():
    groups = group_licenses([
        {
            "folder": "svc",
            "pkg": "jakarta.transaction:jakarta.transaction-api",
            "license": "LicenseRef-GPL-2-0-only-WITH-classpath-exception",
            "severity": "MEDIUM",
            "filepath": "pkg:maven/jakarta.transaction/jakarta.transaction-api@1.3.3",
            "target": "SBOM.cdx-fix.json",
        },
        {
            "folder": "svc",
            "pkg": "jakarta.transaction:jakarta.transaction-api",
            "license": "LicenseRef-GPL-2-0-only-WITH-classpath-exception",
            "severity": "UNKNOWN",
            "filepath": "pkg:maven/jakarta.transaction/jakarta.transaction-api@1.3.3",
            "target": "SBOM.cdx-fix.json",
        },
    ])

    assert len(groups) == 1
    assert [(row["license"], row["severity"]) for row in groups[0]["licenses"]] == [
        ("LicenseRef-GPL-2-0-only-WITH-classpath-exception", "HIGH")
    ]
    assert groups[0]["severity"] == "HIGH"
