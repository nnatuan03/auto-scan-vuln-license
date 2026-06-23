from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Project:
    path: Path
    name: str
    kind: str
    markers: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["path"] = str(self.path)
        return data


@dataclass
class CommandRecord:
    command: list[str]
    cwd: str
    returncode: int
    duration_seconds: float
    stdout_tail: list[str] = field(default_factory=list)
    stderr_tail: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    name: str
    project_path: Path
    project_kind: str
    output_dir: Path
    project_markers: list[str] = field(default_factory=list)
    status: str = "FAIL"
    sbom_status: str = "-"
    sbom_path: Path | None = None
    fixed_sbom_path: Path | None = None
    report_json: Path | None = None
    report_html: Path | None = None
    license_json: Path | None = None
    license_txt: Path | None = None
    vuln_json: Path | None = None
    vuln_html: Path | None = None
    filesystem_report_json: Path | None = None
    vuln_count: int = 0
    license_count: int = 0
    filesystem_vuln_count: int = 0
    filesystem_license_count: int = 0
    misconfig_count: int = 0
    secret_count: int = 0
    elapsed_seconds: float = 0.0
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    commands: list[CommandRecord] = field(default_factory=list)
    debug: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        for key in (
            "project_path",
            "output_dir",
            "sbom_path",
            "fixed_sbom_path",
            "report_json",
            "report_html",
            "license_json",
            "license_txt",
            "vuln_json",
            "vuln_html",
            "filesystem_report_json",
        ):
            data[key] = str(data[key]) if data[key] else None
        data["commands"] = [
            c.to_json() if hasattr(c, "to_json") else c
            for c in self.commands
        ]
        return data
