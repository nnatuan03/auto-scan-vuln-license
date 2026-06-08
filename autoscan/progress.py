from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from .models import Project, ScanResult
from .terminal import colorize, print_lines, status_label


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

        lines = [
            "",
            colorize("Auto Scan Dashboard", "bold", stream=self.stream),
            "===================",
        ]
        stage_color = "green" if self.current_stage == "finished" else "cyan"
        lines.append(f"Stage    : {colorize(self.current_stage, stage_color, stream=self.stream)}")
        if self.root:
            lines.append(f"Root     : {self.root}")
        if self.run_dir:
            lines.append(f"Run dir  : {self.run_dir}")
        bar = _progress_bar(percent)
        lines.append(f"Progress : [{colorize(bar, 'blue', stream=self.stream)}] {self.completed}/{self.total} ({percent:5.1f}%)")
        lines.append(
            "Status   : "
            f"DONE={self.completed} "
            f"OK={colorize(str(self.ok), 'green', stream=self.stream)} "
            f"FAIL={colorize(str(self.failed), 'red', stream=self.stream)} "
            f"RUNNING={colorize(str(running), 'yellow', stream=self.stream)}"
        )
        lines.append(f"Elapsed  : {_format_duration(elapsed)}")
        lines.append(f"ETA      : {_format_duration(self._eta_seconds())}")
        if projects:
            kinds = ", ".join(sorted({project.kind for project in projects}))
            lines.append(f"Detected : {len(projects)} project(s) [{kinds or '-'}]")
        if result:
            lines.append(
                "Last     : "
                f"[{status_label(result.status)}] {result.name} "
                f"kind={result.project_kind} "
                f"sbom={result.sbom_status} "
                f"vulns={result.vuln_count} "
                f"licenses={result.license_count}"
            )
        print_lines(lines, stream=self.stream)
