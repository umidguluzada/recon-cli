"""Target and port-list parsing."""

from __future__ import annotations

import unittest

from utils.validators import parse_ports, parse_target


class ParseTargetTests(unittest.TestCase):
    def test_bare_domain_defaults_to_https(self) -> None:
        target = parse_target("Example.COM")
        self.assertEqual(target.host, "example.com")
        self.assertIsNone(target.scheme)
        self.assertEqual(target.url, "https://example.com")
        self.assertFalse(target.is_ip)

    def test_url_keeps_scheme_port_and_path(self) -> None:
        target = parse_target("https://example.com:8443/health")
        self.assertEqual(target.scheme, "https")
        self.assertEqual(target.port, 8443)
        self.assertEqual(target.path, "/health")
        self.assertEqual(target.url, "https://example.com:8443/health")

    def test_ipv6_loopback(self) -> None:
        target = parse_target("[::1]:8080")
        self.assertTrue(target.is_ip)
        self.assertEqual(target.host, "::1")
        self.assertEqual(target.port, 8080)
        self.assertEqual(target.url, "https://[::1]:8080")

    def test_rejects_credentials_and_queries(self) -> None:
        with self.assertRaises(ValueError):
            parse_target("https://user:secret@example.com")
        with self.assertRaises(ValueError):
            parse_target("https://example.com/path?token=1")

    def test_localhost(self) -> None:
        target = parse_target("localhost")
        self.assertEqual(target.host, "localhost")
        self.assertFalse(target.is_ip)


class ParsePortsTests(unittest.TestCase):
    def test_list_and_range(self) -> None:
        self.assertEqual(parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])

    def test_deduplicates_and_sorts(self) -> None:
        self.assertEqual(parse_ports("443,80,80"), [80, 443])

    def test_rejects_oversized_range(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("1-3000")

    def test_rejects_garbage(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("http")


if __name__ == "__main__":
    unittest.main()
