from __future__ import annotations

from pathlib import Path

from . import merge_report, single_report


def generate_single_report(report_json: Path, output_html: Path) -> Path:
    single_report.generate_html(str(report_json), str(output_html))
    return output_html


def generate_merged_report(services_dir: Path, output_html: Path) -> Path:
    merge_report.generate_html(str(services_dir), str(output_html))
    return output_html
