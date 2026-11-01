"""JSON and HTML report rendering."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from utils.models import ModuleResult, ParsedTarget
from utils.reporter import Reporter
from utils.validators import parse_target


def _result(name: str, findings: list, **meta: object) -> ModuleResult:
    labels = {"subdomains": "Subdomains", "ports": "Port scan", "headers": "Header audit"}
    return ModuleResult(
        name=name,
        label=labels[name],
        status="success",
        started_at="2026-11-01T00:00:00+00:00",
        finished_at="2026-11-01T00:00:01+00:00",
        duration_ms=25,
        findings=findings,
        errors=[],
        meta=dict(meta),
    )


class ReportTests(unittest.TestCase):
    def _reporter(self) -> Reporter:
        target: ParsedTarget = parse_target("example.com")
        reporter = Reporter(target, {"modules": ["subdomains", "ports", "headers"]})
        reporter.add(_result("subdomains", ['www.example.com', '"><script>alert(1)</script>'], display_count=2))
        reporter.add(
            _result(
                "ports",
                [{"port": 443, "protocol": "tcp", "state": "open", "service": "HTTPS"}],
                scanned_address="93.184.216.34",
                ports_scanned=13,
                display_count=1,
            )
        )
        reporter.add(
            _result(
                "headers",
                [
                    {
                        "name": "Content-Security-Policy",
                        "category": "security_header",
                        "status": "missing",
                        "severity": "medium",
                        "value": None,
                        "detail": "Header was not present on the final response.",
                        "recommendation": "Publish a Content-Security-Policy.",
                    }
                ],
                final_url="https://example.com/",
                status_code=200,
                display_count=1,
                issue_count=1,
            )
        )
        return reporter

    def test_json_schema_and_summary(self) -> None:
        report = self._reporter().build()
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["target"]["host"], "example.com")
        self.assertEqual(report["summary"]["subdomains"], 2)
        self.assertEqual(report["summary"]["open_ports"], 1)
        self.assertEqual(report["summary"]["header_issues"], 1)
        self.assertEqual(report["summary"]["highest_severity"], "medium")
        self.assertIn("subdomains", report["modules"])

    def test_writes_json_and_escaped_html(self) -> None:
        reporter = self._reporter()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            json_path = root / "nested" / "report.json"
            html_path = root / "nested" / "report.html"
            reporter.export_json(json_path)
            reporter.export_html(html_path)

            saved = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["tool"], "recon-cli")
            page = html_path.read_text(encoding="utf-8")

        self.assertIn("Filter subdomains", page)
        self.assertIn("data-severity-filter", page)
        self.assertIn("Findings", page)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("Content-Security-Policy", page)


if __name__ == "__main__":
    unittest.main()
