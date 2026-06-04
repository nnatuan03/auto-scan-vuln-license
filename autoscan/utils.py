from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterable, Mapping

from .models import CommandRecord


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-")
    return cleaned or "project"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def first_existing_tool(names: Iterable[str]) -> str | None:
    for name in names:
        if tool_exists(name):
            return name
    return None


def run_command(
    command: list[str],
    cwd: Path,
    log_file: Path | None = None,
    timeout: int | None = None,
    env: Mapping[str, str] | None = None,
) -> tuple[CommandRecord, str, str]:
    start = time.monotonic()
    stdout = ""
    stderr = ""
    returncode = 1
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=dict(env) if env is not None else None,
            shell=False,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        returncode = completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + f"\nCommand timed out after {timeout}s"
        returncode = 124
    except OSError as exc:
        stderr = str(exc)
        returncode = 127

    duration = time.monotonic() - start
    record = CommandRecord(
        command=command,
        cwd=str(cwd),
        returncode=returncode,
        duration_seconds=round(duration, 3),
    )

    if log_file:
        with log_file.open("a", encoding="utf-8") as fh:
            fh.write(f"\n$ {' '.join(command)}\n")
            fh.write(f"[cwd] {cwd}\n")
            fh.write(f"[exit] {returncode} ({duration:.2f}s)\n")
            if stdout:
                fh.write("[stdout]\n")
                fh.write(stdout)
                if not stdout.endswith("\n"):
                    fh.write("\n")
            if stderr:
                fh.write("[stderr]\n")
                fh.write(stderr)
                if not stderr.endswith("\n"):
                    fh.write("\n")

    return record, stdout, stderr


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: Path, data: object) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def count_trivy_findings(report_json: Path) -> tuple[int, int]:
    vuln_count = 0
    license_count = 0
    data = load_json(report_json)
    for result in data.get("Results", []) or []:
        vuln_count += len(result.get("Vulnerabilities") or [])
        license_count += len(result.get("Licenses") or [])
    return vuln_count, license_count


def copy_file(src: Path, dst: Path) -> Path:
    ensure_dir(dst.parent)
    shutil.copy2(src, dst)
    return dst
