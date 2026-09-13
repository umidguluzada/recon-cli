"""
Reporting utility: renders results as rich terminal tables and
optionally exports them to a JSON file.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from rich.console import Console
from rich.table import Table

console = Console()


class Reporter:
    """Collects scan results and renders/exports them."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.data: Dict[str, Any] = {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subdomains": [],
            "open_ports": [],
            "http_headers": {},
        }

    def add_subdomains(self, subdomains: List[str]) -> None:
        self.data["subdomains"] = subdomains

    def add_open_ports(self, open_ports: List[Dict[str, str]]) -> None:
        self.data["open_ports"] = open_ports

    def add_http_headers(self, headers: Dict[str, str]) -> None:
        self.data["http_headers"] = headers

    def print_subdomains_table(self) -> None:
        table = Table(title=f"Subdomains — {self.target}")
        table.add_column("#", style="dim", width=4)
        table.add_column("Subdomain", style="cyan")

        subdomains = self.data["subdomains"]
        if not subdomains:
            console.print("[yellow]No subdomains found.[/yellow]")
            return

        for idx, sub in enumerate(subdomains, start=1):
            table.add_row(str(idx), sub)

        console.print(table)

    def print_ports_table(self) -> None:
        table = Table(title=f"Open Ports — {self.target}")
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("State", style="green")
        table.add_column("Service", style="magenta")

        open_ports = self.data["open_ports"]
        if not open_ports:
            console.print("[yellow]No open ports found.[/yellow]")
            return

        for entry in open_ports:
            table.add_row(str(entry["port"]), entry["state"], entry["service"])

        console.print(table)

    def print_headers_table(self) -> None:
        headers = self.data["http_headers"]
        table = Table(title=f"HTTP Security Headers — {self.target}")
        table.add_column("Header", style="cyan")
        table.add_column("Status")

        if "_error" in headers:
            console.print(f"[red]Error: {headers['_error']}[/red]")
            return

        for key, value in headers.items():
            if key.startswith("_"):
                continue
            style = "green" if value == "PRESENT" else "red"
            table.add_row(key, f"[{style}]{value}[/{style}]")

        console.print(table)

    def export_json(self, output_path: str) -> None:
        """Write all collected results to a JSON file."""
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=4, ensure_ascii=False)
            console.print(f"[green]✔ Report saved to {output_path}[/green]")
        except OSError as exc:
            console.print(f"[red]✘ Failed to write report: {exc}[/red]")
