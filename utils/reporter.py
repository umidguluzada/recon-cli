"""Terminal tables plus JSON and HTML report export."""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from utils.console import console
from utils.constants import MAX_TABLE_ROWS, SCHEMA_VERSION, SEVERITY_RANK, TOOL_NAME, VERSION
from utils.html_report import render_html
from utils.models import ModuleResult, ParsedTarget
from utils.text import NOTICE, format_duration

_STATUS_STYLE = {
    "success": "green",
    "partial": "yellow",
    "error": "red",
    "open": "green",
    "present": "green",
    "missing": "red",
    "weak": "yellow",
    "not_applicable": "dim",
    "skipped": "yellow",
}
_SEVERITY_STYLE = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

class Reporter:
    """Collects module results and renders them for the terminal and for files."""

    def __init__(
        self,
        target: ParsedTarget,
        options: dict[str, Any],
        output: Console | None = None,
    ) -> None:
        self.target = target
        self.options = options
        self.console = output or console
        self.results: list[ModuleResult] = []
        self.started_at = datetime.now(timezone.utc)
        self._clock = time.perf_counter()

    def add(self, result: ModuleResult) -> None:
        self.results.append(result)

    def build(self) -> dict[str, Any]:
        finished_at = datetime.now(timezone.utc)
        modules = {result.name: result.to_dict() for result in self.results}
        summary = _summarize(self.results)
        return {
            "tool": TOOL_NAME,
            "version": VERSION,
            "schema_version": SCHEMA_VERSION,
            "notice": NOTICE,
            "target": self.target.to_dict(),
            "started_at": self.started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_ms": round((time.perf_counter() - self._clock) * 1000, 2),
            "options": self.options,
            "summary": summary,
            "modules": modules,
        }

    def print_banner(self, modules: list[str]) -> None:
        body = Table.grid(padding=(0, 2))
        body.add_column(style="dim")
        body.add_column()
        body.add_row("Target", Text(self.target.raw, style="bold cyan"))
        body.add_row("Host", self.target.host)
        body.add_row("Modules", ", ".join(modules) if modules else "none")
        if self.target.url:
            body.add_row("HTTP", self.target.url)
        self.console.print(
            Panel(
                body,
                title=f"[bold]{TOOL_NAME} {VERSION}[/bold]",
                subtitle="authorized testing only",
                border_style="cyan",
            )
        )

    def print_module(self, result: ModuleResult) -> None:
        printer = {
            "subdomains": self._print_subdomains,
            "ports": self._print_ports,
            "headers": self._print_headers,
        }.get(result.name, self._print_generic)
        printer(result)

    def print_summary(self) -> None:
        summary = _summarize(self.results)
        table = Table(
            title="Run summary",
            box=box.ROUNDED,
            header_style="bold cyan",
            expand=False,
        )
        table.add_column("Module")
        table.add_column("Status")
        table.add_column("Count", justify="right")
        table.add_column("Duration", justify="right")
        table.add_column("Notes")

        for result in self.results:
            status_style = _STATUS_STYLE.get(result.status, "white")
            note = result.errors[0] if result.errors else _module_note(result)
            table.add_row(
                result.label,
                Text(result.status, style=status_style),
                str(result.display_count),
                format_duration(result.duration_ms),
                Text(note, style="dim"),
            )

        self.console.print(table)
        highest = summary["highest_severity"] or "none"
        outcome = "completed" if summary["ok"] else "completed with module errors"
        self.console.print(
            f"[bold]{outcome}[/bold]  "
            f"subdomains [cyan]{summary['subdomains']}[/cyan]  "
            f"open ports [cyan]{summary['open_ports']}[/cyan]  "
            f"header issues [cyan]{summary['header_issues']}[/cyan]  "
            f"highest severity [cyan]{highest}[/cyan]"
        )

    def export_json(self, destination: str | Path, *, stream: TextIO | None = None) -> None:
        payload = json.dumps(self.build(), indent=2, ensure_ascii=False)
        if str(destination) == "-":
            handle = stream or sys.stdout
            handle.write(payload)
            handle.write("\n")
            handle.flush()
            self.console.print("[green]JSON report written to stdout[/green]")
            return

        path = _prepare(destination)
        path.write_text(payload + "\n", encoding="utf-8")
        self.console.print(f"[green]JSON report saved to[/green] {path}")

    def export_html(self, destination: str | Path) -> None:
        path = _prepare(destination)
        path.write_text(render_html(self.build()), encoding="utf-8")
        self.console.print(f"[green]HTML report saved to[/green] {path}")

    def _print_subdomains(self, result: ModuleResult) -> None:
        names = [str(item) for item in result.findings]
        if result.status == "skipped":
            reason = str(result.meta.get("reason") or "Module skipped.")
            self.console.print(f"[yellow]{reason}[/yellow]")
            return
        if result.status == "error" and not names:
            self._print_failure(result)
            return
        if not names:
            self.console.print("[yellow]No subdomains found.[/yellow]")
            return

        shown, hidden = _window(names)
        table = Table(
            title=f"Subdomains — {self.target.host}",
            caption=f"{len(names)} name(s)" + (f", showing {len(shown)}" if hidden else ""),
            box=box.ROUNDED,
            header_style="bold cyan",
        )
        table.add_column("#", style="dim", justify="right")
        table.add_column("Subdomain")
        for index, name in enumerate(shown, start=1):
            table.add_row(str(index), name)
        self.console.print(table)
        if hidden:
            self.console.print(
                f"[dim]{hidden} more subdomain(s) are included in the JSON and HTML reports.[/dim]"
            )

    def _print_ports(self, result: ModuleResult) -> None:
        if result.status == "error" and not result.findings:
            self._print_failure(result)
            return
        if not result.findings:
            scanned = result.meta.get("ports_scanned", 0)
            self.console.print(f"[yellow]No open ports found ({scanned} checked).[/yellow]")
            return

        address = result.meta.get("scanned_address", self.target.host)
        table = Table(
            title=f"Open ports — {address}",
            caption=f"{len(result.findings)} open / {result.meta.get('ports_scanned', '?')} scanned",
            box=box.ROUNDED,
            header_style="bold cyan",
        )
        table.add_column("Port", justify="right", style="cyan")
        table.add_column("Proto")
        table.add_column("State")
        table.add_column("Service")
        for entry in result.findings:
            table.add_row(
                str(entry["port"]),
                str(entry.get("protocol", "tcp")),
                Text(str(entry.get("state", "open")), style="green"),
                str(entry.get("service", "unknown")),
            )
        self.console.print(table)

    def _print_headers(self, result: ModuleResult) -> None:
        if result.status == "error" and not result.findings:
            self._print_failure(result)
            return
        final_url = result.meta.get("final_url") or result.meta.get("requested_url") or self.target.url
        status_code = result.meta.get("status_code")
        caption = f"{final_url}"
        if status_code is not None:
            caption = f"HTTP {status_code}  {final_url}"

        table = Table(
            title=f"HTTP security headers — {self.target.host}",
            caption=caption,
            box=box.ROUNDED,
            header_style="bold cyan",
        )
        table.add_column("Header", style="cyan")
        table.add_column("Status")
        table.add_column("Severity")
        table.add_column("Value")
        for finding in result.findings:
            status = str(finding.get("status", ""))
            severity = str(finding.get("severity", "info"))
            value = finding.get("value") or "—"
            table.add_row(
                str(finding.get("name", "")),
                Text(status, style=_STATUS_STYLE.get(status, "white")),
                Text(severity, style=_SEVERITY_STYLE.get(severity, "white")),
                Text(str(value)),
            )
        self.console.print(table)

    def _print_generic(self, result: ModuleResult) -> None:
        self.console.print(f"{result.label}: {result.status} ({result.display_count})")

    def _print_failure(self, result: ModuleResult) -> None:
        detail = result.errors[0] if result.errors else "module failed"
        self.console.print(f"[red]{result.label} failed:[/red] {detail}")


def _window(items: list[str]) -> tuple[list[str], int]:
    if len(items) <= MAX_TABLE_ROWS:
        return items, 0
    return items[:MAX_TABLE_ROWS], len(items) - MAX_TABLE_ROWS


def _module_note(result: ModuleResult) -> str:
    if result.status == "skipped":
        return "not a domain" if result.name == "subdomains" else "skipped"
    if result.name == "ports":
        address = result.meta.get("scanned_address")
        return f"scanned {address}" if address else ""
    if result.name == "headers":
        code = result.meta.get("status_code")
        return f"HTTP {code}" if code else ""
    if result.name == "subdomains":
        source = result.meta.get("source")
        return str(source) if source else ""
    return ""


def _summarize(results: list[ModuleResult]) -> dict[str, Any]:
    subdomains = 0
    open_ports = 0
    header_issues = 0
    highest: str | None = None

    for result in results:
        if result.name == "subdomains":
            subdomains = len(result.findings)
        elif result.name == "ports":
            open_ports = len(result.findings)
        elif result.name == "headers":
            for finding in result.findings:
                if not isinstance(finding, dict):
                    continue
                if finding.get("status") not in {"missing", "weak"}:
                    continue
                severity = str(finding.get("severity", "info"))
                if severity not in {"low", "medium", "high", "critical"}:
                    continue
                header_issues += 1
                if highest is None or SEVERITY_RANK[severity] > SEVERITY_RANK.get(highest, 0):
                    highest = severity

    failed = sum(1 for result in results if result.status == "error")
    return {
        "modules_run": len(results),
        "modules_failed": failed,
        "ok": failed == 0 and bool(results),
        "subdomains": subdomains,
        "open_ports": open_ports,
        "header_issues": header_issues,
        "highest_severity": highest,
    }


def _prepare(destination: str | Path) -> Path:
    path = Path(destination)
    if path.parent and str(path.parent) not in {"", "."}:
        path.parent.mkdir(parents=True, exist_ok=True)
    return path
