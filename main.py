#!/usr/bin/env python3
"""
Recon CLI — Penetration Testing & Reconnaissance Tool
Licensed under Apache-2.0.

Entry point: parses CLI arguments and orchestrates the recon modules.
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from modules.subdomain import SubdomainEnumerator
from modules.port_scanner import PortScanner
from modules.http_audit import HTTPAuditor
from utils.reporter import Reporter

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-cli",
        description="Open-source Penetration Testing & Reconnaissance CLI tool.",
    )
    parser.add_argument(
        "target",
        help="Target domain or IP address (e.g. example.com)",
    )
    parser.add_argument(
        "--subdomains",
        action="store_true",
        help="Enumerate subdomains via crt.sh",
    )
    parser.add_argument(
        "--ports",
        action="store_true",
        help="Run asynchronous port scan against the target",
    )
    parser.add_argument(
        "--headers",
        action="store_true",
        help="Audit HTTP security headers on the target",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all available modules",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write full results to a JSON file (e.g. report.json)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Timeout in seconds for port scan connections (default: 1.5)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=100,
        help="Maximum concurrent port scan connections (default: 100)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not (args.subdomains or args.ports or args.headers or args.all):
        console.print(
            "[yellow]No module selected. Use --subdomains, --ports, --headers or --all.[/yellow]"
        )
        parser.print_help()
        return 1

    target = args.target
    reporter = Reporter(target)

    console.rule(f"[bold cyan]Recon CLI — Target: {target}[/bold cyan]")

    if args.subdomains or args.all:
        console.print("[bold]-> Running subdomain enumeration...[/bold]")
        try:
            enumerator = SubdomainEnumerator(domain=target)
            subdomains = enumerator.enumerate()
            reporter.add_subdomains(subdomains)
            reporter.print_subdomains_table()
        except Exception as exc:
            console.print(f"[red]X Subdomain enumeration failed: {exc}[/red]")

    if args.ports or args.all:
        console.print("[bold]-> Running port scan...[/bold]")
        try:
            scanner = PortScanner(
                target=target,
                timeout=args.timeout,
                concurrency=args.concurrency,
            )
            open_ports = scanner.run()
            reporter.add_open_ports(open_ports)
            reporter.print_ports_table()
        except Exception as exc:
            console.print(f"[red]X Port scan failed: {exc}[/red]")

    if args.headers or args.all:
        console.print("[bold]-> Auditing HTTP security headers...[/bold]")
        try:
            auditor = HTTPAuditor(url=target)
            headers_result = auditor.audit()
            reporter.add_http_headers(headers_result)
            reporter.print_headers_table()
        except Exception as exc:
            console.print(f"[red]X HTTP header audit failed: {exc}[/red]")

    if args.output:
        reporter.export_json(args.output)

    console.rule("[bold cyan]Done[/bold cyan]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
