"""Header classification plus local async scans against 127.0.0.1."""

from __future__ import annotations

import asyncio
import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer

from main import main
from modules.base import ReconModule
from modules.http_audit import HTTPAuditor, evaluate_headers, issue_count
from modules.port_scanner import COMMON_PORTS, TOP_100_PORTS, PortScanner
from utils.validators import parse_target


class HeaderEvaluationTests(unittest.TestCase):
    def test_missing_and_weak_headers_on_https(self) -> None:
        findings = evaluate_headers(
            {
                "Strict-Transport-Security": "max-age=0",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "frame-ancestors 'none'",
                "Server": "Example/1.2.3",
            },
            final_url="https://example.com/",
        )
        by_name = {item["name"]: item for item in findings}
        self.assertEqual(by_name["Strict-Transport-Security"]["status"], "weak")
        self.assertEqual(by_name["X-Content-Type-Options"]["status"], "present")
        self.assertEqual(by_name["X-Frame-Options"]["status"], "present")
        self.assertEqual(by_name["Content-Security-Policy"]["status"], "present")
        self.assertEqual(by_name["Server"]["category"], "information_disclosure")
        self.assertGreaterEqual(issue_count(findings), 1)

    def test_hsts_is_not_applicable_on_plain_http(self) -> None:
        findings = evaluate_headers({}, final_url="http://example.com/")
        hsts = next(item for item in findings if item["name"] == "Strict-Transport-Security")
        self.assertEqual(hsts["status"], "not_applicable")
        self.assertEqual(issue_count([hsts]), 0)


class PortProfileTests(unittest.TestCase):
    def test_profiles_are_unique_and_in_range(self) -> None:
        self.assertEqual(len(TOP_100_PORTS), 100)
        self.assertEqual(len(set(TOP_100_PORTS)), 100)
        self.assertTrue(all(1 <= port <= 65535 for port in TOP_100_PORTS))
        self.assertEqual(len(set(COMMON_PORTS)), len(COMMON_PORTS))


class _Boom(ReconModule):
    name = "boom"
    label = "Boom"

    async def execute(self):  # type: ignore[no-untyped-def]
        raise RuntimeError("nope")


class _Slow(ReconModule):
    name = "slow"
    label = "Slow"

    async def execute(self):  # type: ignore[no-untyped-def]
        await asyncio.sleep(2)
        return [], {}


class ModuleIsolationTests(unittest.TestCase):
    def test_exception_stays_inside_the_module(self) -> None:
        result = asyncio.run(_Boom(module_timeout=5).run())
        self.assertEqual(result.status, "error")
        self.assertIn("nope", result.errors[0])

    def test_module_timeout(self) -> None:
        result = asyncio.run(_Slow(module_timeout=0.05).run())
        self.assertEqual(result.status, "error")
        self.assertIn("timed out", result.errors[0])


class LocalScanTests(unittest.TestCase):
    def test_port_scanner_finds_local_listener(self) -> None:
        async def scenario() -> None:
            async def _handle(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(_handle, "127.0.0.1", 0)
            sockets = server.sockets or []
            open_port = sockets[0].getsockname()[1]
            with socket.socket() as closed_sock:
                closed_sock.bind(("127.0.0.1", 0))
                closed_port = closed_sock.getsockname()[1]

            scanner = PortScanner(
                parse_target("127.0.0.1"),
                ports=[open_port, closed_port],
                timeout=1,
                concurrency=4,
                module_timeout=10,
            )
            try:
                result = await scanner.run()
            finally:
                server.close()
                await server.wait_closed()

            self.assertEqual(result.status, "success")
            found = {item["port"] for item in result.findings}
            self.assertIn(open_port, found)
            self.assertNotIn(closed_port, found)
            self.assertEqual(result.meta["scanned_address"], "127.0.0.1")

        asyncio.run(scenario())

    def test_header_audit_against_local_server(self) -> None:
        async def scenario() -> None:
            async def handler(_request: web.Request) -> web.Response:
                return web.Response(
                    text="ok",
                    headers={
                        "X-Content-Type-Options": "nosniff",
                        "X-Frame-Options": "DENY",
                        "Server": "recon-cli-test",
                    },
                )

            app = web.Application()
            app.router.add_get("/", handler)
            server = TestServer(app)
            await server.start_server()
            try:
                target = parse_target(f"http://127.0.0.1:{server.port}/")
                async with aiohttp.ClientSession() as session:
                    auditor = HTTPAuditor(target, session, timeout=5, module_timeout=15)
                    result = await auditor.run()
            finally:
                await server.close()

            self.assertEqual(result.status, "success")
            self.assertEqual(result.meta["status_code"], 200)
            by_name = {item["name"]: item for item in result.findings}
            self.assertEqual(by_name["X-Content-Type-Options"]["status"], "present")
            self.assertEqual(by_name["X-Frame-Options"]["status"], "present")
            self.assertEqual(by_name["Content-Security-Policy"]["status"], "missing")
            self.assertEqual(by_name["Server"]["value"], "recon-cli-test")

        asyncio.run(scenario())


class CliIntegrationTests(unittest.TestCase):
    def test_quiet_run_writes_reports_for_a_local_service(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                json_path = root / "report.json"
                html_path = root / "report.html"
                code = main(
                    [
                        f"http://127.0.0.1:{port}/",
                        "--ports",
                        "--headers",
                        "--port-list",
                        str(port),
                        "--timeout",
                        "1",
                        "--http-timeout",
                        "5",
                        "--module-timeout",
                        "20",
                        "--output",
                        str(json_path),
                        "--html",
                        str(html_path),
                        "-q",
                    ]
                )
                report = json.loads(json_path.read_text(encoding="utf-8"))
                page = html_path.read_text(encoding="utf-8")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(code, 0)
        self.assertEqual(report["modules"]["ports"]["findings"][0]["port"], port)
        self.assertEqual(report["modules"]["headers"]["meta"]["status_code"], 200)
        self.assertIn("HTTP security headers", page)


if __name__ == "__main__":
    unittest.main()
