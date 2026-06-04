from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .license_rules import update_licenses_and_hashes_in_bom

from .utils import ensure_dir


def normalize_sbom(input_path: Path, output_path: Path, log_path: Path) -> tuple[Path, dict]:
    ensure_dir(output_path.parent)
    ensure_dir(log_path.parent)
    with input_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    updated, stats = update_licenses_and_hashes_in_bom(data, str(log_path))
    updated.setdefault("metadata", {})
    updated["metadata"]["autoscanLicenseNormalizedAt"] = datetime.now(timezone.utc).isoformat()

    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(updated, fh, indent=2, ensure_ascii=False)

    return output_path, stats
