from autoscan.reporting.merge_report import group_vulns


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
