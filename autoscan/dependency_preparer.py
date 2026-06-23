from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from .models import CommandRecord, Project
from .utils import first_existing_tool, run_command

PromptFn = Callable[[str], str]


@dataclass
class PrepareAction:
    project: Project
    command: list[str]
    cwd: Path
    reason: str


@dataclass
class PrepareResult:
    project_name: str
    status: str
    reason: str
    commands: list[CommandRecord] = field(default_factory=list)
    error: str = ""

    def to_json(self) -> dict[str, object]:
        return {
            "project_name": self.project_name,
            "status": self.status,
            "reason": self.reason,
            "error": self.error,
            "commands": [command.to_json() for command in self.commands],
        }


def discover_prepare_actions(projects: Iterable[Project]) -> list[PrepareAction]:
    actions: list[PrepareAction] = []
    flutter = first_existing_tool(("flutter", "flutter.bat"))
    for project in projects:
        if project.kind == "flutter" and project.path.is_dir() and (project.path / "pubspec.yaml").is_file() and not (project.path / "pubspec.lock").is_file():
            if flutter:
                actions.append(PrepareAction(
                    project=project,
                    command=[flutter, "pub", "get"],
                    cwd=project.path,
                    reason="pubspec.yaml exists but pubspec.lock is missing.",
                ))
    return actions


def _confirm_actions(actions: list[PrepareAction], *, prompt: PromptFn = input) -> bool:
    print("\nDependency metadata is missing for some projects:")
    for action in actions:
        print(f"- {action.project.name}: {action.reason} -> {' '.join(action.command)}")
    answer = prompt("Run dependency preparation commands before scanning? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def prepare_dependencies(
    projects: list[Project],
    log_file: Path,
    *,
    enabled: bool = False,
    assume_yes: bool = False,
    prompt: PromptFn = input,
) -> tuple[list[PrepareResult], list[CommandRecord]]:
    if not enabled:
        return [], []

    actions = discover_prepare_actions(projects)
    if not actions:
        return [], []

    if not assume_yes and not sys.stdin.isatty():
        tools = ", ".join(action.project.name for action in actions[:10])
        print(f"[WARN] Dependency preparation needed ({tools}) but stdin is not interactive. Re-run with --prepare-deps-auto or run manually.", file=sys.stderr)
        return [
            PrepareResult(action.project.name, "SKIPPED_NON_INTERACTIVE", action.reason)
            for action in actions
        ], []

    if not assume_yes and not _confirm_actions(actions, prompt=prompt):
        return [
            PrepareResult(action.project.name, "SKIPPED_BY_USER", action.reason)
            for action in actions
        ], []

    results: list[PrepareResult] = []
    records: list[CommandRecord] = []
    for action in actions:
        record, _, _ = run_command(action.command, cwd=action.cwd, log_file=log_file)
        records.append(record)
        if record.returncode == 0 and (action.cwd / "pubspec.lock").is_file():
            results.append(PrepareResult(action.project.name, "OK", action.reason, [record]))
        else:
            error = "Command failed" if record.returncode != 0 else "Command succeeded but pubspec.lock was not created"
            results.append(PrepareResult(action.project.name, "FAIL", action.reason, [record], error))
    return results, records
