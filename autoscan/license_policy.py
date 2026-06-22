from __future__ import annotations

from fnmatch import fnmatchcase

MANIFEST_PACKAGE_NAMES = {
    "pom.xml",
    "pubspec.lock",
    "pubspec.yaml",
    "package-lock.json",
    "package.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}

LICENSE_REF_CLASSIFICATION = {
    "LicenseRef-Public-Domain": ("LOW", "permissive"),
    "LicenseRef-CDDL-GPLv2-CE": ("HIGH", "restricted"),
    "LicenseRef-Oracle-FUTC": ("HIGH", "restricted"),
    "LicenseRef-Oracle-OTN": ("HIGH", "restricted"),
}

PACKAGE_LICENSE_OVERRIDES = {
    "javax.activation:javax.activation-api": "LicenseRef-CDDL-GPLv2-CE",
    "javax.activation/javax.activation-api": "LicenseRef-CDDL-GPLv2-CE",
    "javax.annotation:javax.annotation-api": "LicenseRef-CDDL-GPLv2-CE",
    "javax.annotation/javax.annotation-api": "LicenseRef-CDDL-GPLv2-CE",
    "javax.annotation-api": "LicenseRef-CDDL-GPLv2-CE",
    "com.oracle.database.jdbc:ojdbc8": "LicenseRef-Oracle-FUTC",
    "com.oracle.database.jdbc/ojdbc8": "LicenseRef-Oracle-FUTC",
    "com.oracle.ojdbc:ojdbc8": "LicenseRef-Oracle-FUTC",
    "com.oracle.ojdbc/ojdbc8": "LicenseRef-Oracle-FUTC",
    "io.github.openfeign.querydsl:querydsl-jpa": "Apache-2.0",
    "io.github.openfeign.querydsl/querydsl-jpa": "Apache-2.0",
    "xtend": "MIT",
    "flutter": "BSD-3-Clause",
    "flutter_localizations": "BSD-3-Clause",
    "flutter_test": "BSD-3-Clause",
    "flutter_web_plugins": "BSD-3-Clause",
    "sky_engine": "BSD-3-Clause",
    "html": "MIT",
    "showcaseview": "MIT",
    "aopalliance:aopalliance": "LicenseRef-Public-Domain",
    "aopalliance/aopalliance": "LicenseRef-Public-Domain",
}

PACKAGE_LICENSE_PATTERNS = {
    "io.swagger.parser.v3:swagger-parser-*": "Apache-2.0",
    "io.swagger.parser.v3/swagger-parser-*": "Apache-2.0",
    "org.json:json": "JSON",
    "org.json/json": "JSON",
}


def package_license_override(package_name: str) -> str | None:
    normalized = str(package_name or "").strip()
    if not normalized:
        return None
    variants = {normalized, normalized.replace("/", ":"), normalized.replace(":", "/")}
    for variant in variants:
        if variant in PACKAGE_LICENSE_OVERRIDES:
            return PACKAGE_LICENSE_OVERRIDES[variant]
    for variant in variants:
        for pattern, license_id in PACKAGE_LICENSE_PATTERNS.items():
            if fnmatchcase(variant, pattern):
                return license_id
    return None


def classify_license_ref(name: str) -> tuple[str, str] | None:
    normalized = str(name or "").strip()
    if normalized in LICENSE_REF_CLASSIFICATION:
        return LICENSE_REF_CLASSIFICATION[normalized]
    upper = normalized.upper()
    if "ORACLE" in upper or "OTN" in upper:
        return "HIGH", "restricted"
    if "GPL" in upper or "CLASSPATH" in upper:
        return "HIGH", "restricted"
    if "CDDL" in upper:
        return "MEDIUM", "reciprocal"
    if "PUBLIC-DOMAIN" in upper or "PUBLIC_DOMAIN" in upper:
        return "LOW", "permissive"
    return None


def is_manifest_package_name(package_name: str) -> bool:
    return str(package_name or "").strip().lower() in MANIFEST_PACKAGE_NAMES
