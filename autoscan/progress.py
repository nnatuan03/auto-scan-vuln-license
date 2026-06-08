from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from .models import Project, ScanResult


def _format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "estimating"
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _progress_bar(percent: float, width: int = 30) -> str:
    filled = int(round(width * max(0.0, min(100.0, percent)) / 100.0))
    return "#" * filled + "-" * (width - filled)


@dataclass
class ProgressDashboard:
    enabled: bool = True
    stream: TextIO = sys.stdout
    started_at: float = field(default_factory=time.monotonic)
    total: int = 0
    completed: int = 0
    ok: int = 0
    failed: int = 0
    current_stage: str = "starting"
    root: Path | None = None
    run_dir: Path | None = None

    def __call__(self, event: str, payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        if event == "start":
            self.root = payload.get("root")
            self.run_dir = payload.get("run_dir")
            projects = payload.get("projects") or []
            self.total = int(payload.get("total") or len(projects))
            self.completed = 0
            self.ok = 0
            self.failed = 0
            self.current_stage = "scanning"
            self._render("Scan started", projects=projects)
        elif event == "project_complete":
            result = payload["result"]
            self.completed = int(payload["completed"]) if "completed" in payload else self.completed + 1
            self.ok = int(payload["ok"]) if "ok" in payload else self.ok
            self.failed = int(payload["failed"]) if "failed" in payload else self.failed
            self.current_stage = "scanning"
            self._render("Project completed", result=result)
        elif event == "merge_start":
            self.current_stage = "merging reports"
            self._render("Merging reports")
        elif event == "finish":
            self.current_stage = "finished"
            self.completed = int(payload["completed"]) if "completed" in payload else self.completed
            self.ok = int(payload["ok"]) if "ok" in payload else self.ok
            self.failed = int(payload["failed"]) if "failed" in payload else self.failed
            self._render("Scan finished")

    def _eta_seconds(self) -> float | None:
        if self.completed <= 0 or self.total <= 0:
            return None
        remaining = max(0, self.total - self.completed)
        if remaining == 0:
            return 0.0
        elapsed = time.monotonic() - self.started_at
        return (elapsed / self.completed) * remaining

    def _render(
        self,
        title: str,
        *,
        projects: list[Project] | None = None,
        result: ScanResult | None = None,
    ) -> None:
        elapsed = time.monotonic() - self.started_at
        percent = self.completed / self.total * 100.0 if self.total else 0.0
        running = max(0, self.total - self.completed)

        print("", file=self.stream)
        print("Auto Scan Dashboard", file=self.stream)
        print("===================", file=self.stream)
        print(f"Stage    : {self.current_stage}", file=self.stream)
        if self.root:
            print(f"Root     : {self.root}", file=self.stream)
        if self.run_dir:
            print(f"Run dir  : {self.run_dir}", file=self.stream)
        print(f"Progress : [{_progress_bar(percent)}] {self.completed}/{self.total} ({percent:5.1f}%)", file=self.stream)
        print(f"Status   : DONE={self.completed} OK={self.ok} FAIL={self.failed} RUNNING={running}", file=self.stream)
        print(f"Elapsed  : {_format_duration(elapsed)}", file=self.stream)
        print(f"ETA      : {_format_duration(self._eta_seconds())}", file=self.stream)
        if projects:
            kinds = ", ".join(sorted({project.kind for project in projects}))
            print(f"Detected : {len(projects)} project(s) [{kinds or '-'}]", file=self.stream)
        if result:
            print(
                "Last     : "
                f"[{result.status}] {result.name} "
                f"kind={result.project_kind} "
                f"sbom={result.sbom_status} "
                f"vulns={result.vuln_count} "
                f"licenses={result.license_count}",
                file=self.stream,
            )
        self.stream.flush()
