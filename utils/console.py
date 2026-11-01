"""Terminal logging that stays quiet while progress bars are on screen."""

from __future__ import annotations

import sys

from rich.console import Console

console = Console(stderr=True)


def configure_stdio() -> None:
    """Prefer UTF-8 so status glyphs render in Windows terminals."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue


class ScanLogger:
    """Collects structured log lines and prints them after the live display."""

    def __init__(self, output: Console | None = None, verbose: bool = False) -> None:
        self.console = output or console
        self.verbose = verbose
        self.records: list[tuple[str, str]] = []

    def info(self, message: str) -> None:
        self.records.append(("info", message))

    def warning(self, message: str) -> None:
        self.records.append(("warning", message))

    def error(self, message: str) -> None:
        self.records.append(("error", message))

    def debug(self, message: str) -> None:
        self.records.append(("debug", message))

    def flush(self) -> None:
        styles = {
            "info": "cyan",
            "warning": "yellow",
            "error": "red",
            "debug": "dim",
        }
        for level, message in self.records:
            if level in {"info", "debug"} and not self.verbose:
                continue
            style = styles[level]
            self.console.print(f"[{style}]{level.upper():<7}[/{style}] {message}")
        self.records.clear()
