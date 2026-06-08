from __future__ import annotations

import os
import shlex
import subprocess
import sys
import threading
from pathlib import Path
from typing import TextIO

from .models import CommandRecord


_LOCK = threading.Lock()
_SHOW_COMMANDS = True
_COLOR_MODE = "auto"

COLORS = {
    "reset": "\033[0m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bold": "\033[1m",
}


def configure_terminal(*, show_commands: bool = True, color_mode: str = "auto") -> None:
    global _SHOW_COMMANDS, _COLOR_MODE
    _SHOW_COMMANDS = show_commands
    _COLOR_MODE = color_mode
    if _should_color(sys.stdout):
        _enable_windows_ansi()


def _enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _should_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if _COLOR_MODE == "always":
        return True
    if _COLOR_MODE == "never":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def colorize(text: str, color: str, *, stream: TextIO = sys.stdout) -> str:
    if not _should_color(stream):
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def format_command(command: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline([str(part) for part in command])
    return shlex.join(str(part) for part in command)


def command_started(command: list[str], cwd: Path) -> None:
    if not _SHOW_COMMANDS:
        return
    with _LOCK:
        print(
            f"{colorize('[RUN]', 'cyan')} {format_command(command)}",
            file=sys.stdout,
            flush=True,
        )
        print(
            f"{colorize('      cwd:', 'dim')} {cwd}",
            file=sys.stdout,
            flush=True,
        )


def command_finished(record: CommandRecord) -> None:
    if not _SHOW_COMMANDS:
        return
    ok = record.returncode == 0
    label = colorize("[OK ]", "green") if ok else colorize("[FAIL]", "red")
    with _LOCK:
        print(
            f"{label} exit={record.returncode} time={record.duration_seconds:.2f}s "
            f"{format_command(record.command)}",
            file=sys.stdout,
            flush=True,
        )
        if not ok and record.stderr_tail:
            print(colorize("      stderr tail:", "yellow"), file=sys.stdout, flush=True)
            for line in record.stderr_tail[-5:]:
                print(f"      {line}", file=sys.stdout, flush=True)


def print_lines(lines: list[str], *, stream: TextIO = sys.stdout) -> None:
    with _LOCK:
        for line in lines:
            print(line, file=stream)
        stream.flush()


def status_label(status: str) -> str:
    normalized = status.upper()
    if normalized == "OK":
        return colorize(status, "green")
    if normalized == "FAIL":
        return colorize(status, "red")
    if normalized == "DRYRUN":
        return colorize(status, "cyan")
    return status
