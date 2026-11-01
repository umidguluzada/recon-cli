#!/usr/bin/env python3
"""Recon CLI — asynchronous reconnaissance toolkit. Licensed under MIT."""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any, Sequence

import aiohttp
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from modules.base import ReconModule
from modules.http_audit import HTTPAuditor
from modules.port_scanner import TOP_100_PORTS, PortScanner
from modules.subdomain import SubdomainEnumerator
from utils.console import ScanLogger, configure_stdio, console
from utils.constants import (
    DEFAULT_CONCURRENCY,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_MODULE_TIMEOUT,
    DEFAULT_PORT_TIMEOUT,
    DEFAULT_RETRIES,
    MAX_CONCURRENCY,
    TOOL_NAME,
    USER_AGENT,
    VERSION,
)
from utils.models import ModuleResult, ParsedTarget
from utils.reporter import Reporter
from utils.validators import parse_ports, parse_target

_EPILOG = """\
examples:
  python main.py example.com --all --output report.json --html report.html
  python main.py example.com --subdomains
  python main.py example.com --ports --timeout 2 --concurrency 200
  python main.py example.com --top 100
  python main.py example.com --port-list 22,80,443,8000-8080
  python main.py https://example.com --headers

Only scan systems you are authorized to test.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Asynchronous reconnaissance CLI for subdomain enumeration, "
            "TCP connect scanning, and HTTP security-header audits."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    parser.add_argument("target", help="Domain, IP address, or http(s) URL")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate names from crt.sh")
    parser.add_argument("--ports", action="store_true", help="TCP connect scan of common ports")
    parser.add_argument("--headers", action="store_true", help="Audit HTTP security headers")
    parser.add_argument("--all", action="store_true", help="Run every module")
    parser.add_argument(
        "--port-list",
        metavar="PORTS",
        help="Ports or ranges to scan (for example 22,80,443,8000-8080). Implies --ports",
    )
    parser.add_argument(
        "--top",
        type=int,
        choices=(100,),
        help="Scan the curated set of 100 common TCP ports. Implies --ports",
    )
    parser.add_argument("--output", "-o", metavar="FILE", help="Write JSON to FILE, or '-' for stdout")
    parser.add_argument("--html", metavar="FILE", help="Write a self-contained interactive HTML report")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_PORT_TIMEOUT,
        help=f"Per-port TCP timeout in seconds (default: {DEFAULT_PORT_TIMEOUT})",
    )
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=DEFAULT_HTTP_TIMEOUT,
        help=f"Timeout for crt.sh and the header audit in seconds (default: {DEFAULT_HTTP_TIMEOUT})",
    )
    parser.add_argument(
        "--module-timeout",
        type=float,
        default=DEFAULT_MODULE_TIMEOUT,
        help=f"Overall timeout for each module in seconds (default: {DEFAULT_MODULE_TIMEOUT})",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Maximum in-flight TCP connections (default: {DEFAULT_CONCURRENCY})",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"Attempts for a transient crt.sh failure (default: {DEFAULT_RETRIES})",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Do not verify TLS certificates during the header audit",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show retry and DNS details")
    parser.add_argument("-q", "--quiet", action="store_true", help="Hide the banner and finding tables")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {VERSION}")
    return parser


def _validate(args: argparse.Namespace) -> None:
    bounds = (
        (args.timeout, 30.0, "--timeout"),
        (args.http_timeout, 120.0, "--http-timeout"),
        (args.module_timeout, 3600.0, "--module-timeout"),
    )
    for value, upper, flag in bounds:
        if not 0 < value <= upper:
            raise ValueError(f"{flag} must be greater than 0 and at most {upper:g}.")
    if not 1 <= args.concurrency <= MAX_CONCURRENCY:
        raise ValueError(f"--concurrency must be between 1 and {MAX_CONCURRENCY}.")
    if not 1 <= args.retries <= 8:
        raise ValueError("--retries must be between 1 and 8.")
    if args.quiet and args.verbose:
        raise ValueError("Choose either --quiet or --verbose.")
    if args.port_list and args.top:
        raise ValueError("Use either --port-list or --top, not both.")


def _selected_ports(args: argparse.Namespace) -> list[int] | None:
    if args.port_list:
        return parse_ports(args.port_list)
    if args.top:
        return list(TOP_100_PORTS)
    return None


def _module_names(args: argparse.Namespace) -> list[str]:
    names: list[str] = []
    if args.subdomains or args.all:
        names.append("subdomains")
    if args.ports or args.port_list or args.top or args.all:
        names.append("ports")
    if args.headers or args.all:
        names.append("headers")
    return names


def _options(args: argparse.Namespace, modules: Sequence[str]) -> dict[str, Any]:
    return {
        "modules": list(modules),
        "timeout": args.timeout,
        "http_timeout": args.http_timeout,
        "module_timeout": args.module_timeout,
        "concurrency": args.concurrency,
        "retries": args.retries,
        "port_list": args.port_list,
        "top": args.top,
        "insecure": args.insecure,
    }


async def _run_modules(modules: Sequence[ReconModule], *, quiet: bool) -> list[ModuleResult]:
    if quiet:
        return list(await asyncio.gather(*(module.run() for module in modules)))

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )
    with progress:
        task_ids = [
            progress.add_task(module.label, total=module.total_steps) for module in modules
        ]

        async def _one(module: ReconModule, task_id: int) -> ModuleResult:
            result = await module.run(
                on_advance=lambda steps, task_id=task_id: progress.advance(task_id, steps)
            )
            task = next(item for item in progress.tasks if item.id == task_id)
            total = task.total or 1
            style = {"success": "green", "partial": "yellow", "skipped": "yellow"}.get(
                result.status, "red"
            )
            progress.update(
                task_id,
                total=total,
                completed=total,
                description=f"{module.label} [{style}]{result.status}[/{style}]",
            )
            return result

        grouped = zip(modules, task_ids)
        return list(await asyncio.gather(*(_one(module, task_id) for module, task_id in grouped)))


async def async_main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    modules = _module_names(args)
    if not modules:
        console.print(
            "[yellow]No module selected.[/yellow] Choose --subdomains, --ports, --headers, or --all."
        )
        parser.print_help(sys.stderr)
        return 2

    try:
        _validate(args)
        target: ParsedTarget = parse_target(args.target)
        ports = _selected_ports(args)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    logger = ScanLogger(verbose=args.verbose)
    if args.insecure:
        logger.warning("[headers] TLS certificate verification is disabled.")

    reporter = Reporter(target, _options(args, modules))
    if not args.quiet:
        reporter.print_banner(modules)

    timeout = aiohttp.ClientTimeout(total=args.http_timeout)
    connector = aiohttp.TCPConnector(limit=max(10, args.concurrency))
    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        headers={"User-Agent": USER_AGENT},
        trust_env=False,
    ) as session:
        selected: list[ReconModule] = []
        if "subdomains" in modules:
            selected.append(
                SubdomainEnumerator(
                    target,
                    session,
                    timeout=args.http_timeout,
                    retries=args.retries,
                    module_timeout=args.module_timeout,
                    logger=logger,
                )
            )
        if "ports" in modules:
            selected.append(
                PortScanner(
                    target,
                    ports=ports,
                    timeout=args.timeout,
                    concurrency=args.concurrency,
                    module_timeout=args.module_timeout,
                    logger=logger,
                )
            )
        if "headers" in modules:
            selected.append(
                HTTPAuditor(
                    target,
                    session,
                    timeout=args.http_timeout,
                    insecure=args.insecure,
                    module_timeout=args.module_timeout,
                    logger=logger,
                )
            )
        results = await _run_modules(selected, quiet=args.quiet)

    logger.flush()
    for result in results:
        reporter.add(result)
        if not args.quiet:
            reporter.print_module(result)
    if not args.quiet:
        console.rule()
    reporter.print_summary()

    try:
        if args.output:
            reporter.export_json(args.output)
        if args.html:
            reporter.export_html(args.html)
    except OSError as exc:
        console.print(f"[red]Could not write the report: {exc}[/red]")
        return 1

    if any(result.status == "error" for result in results):
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    configure_stdio()
    try:
        return asyncio.run(async_main(argv))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
