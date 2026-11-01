"""Certificate-log parsing and crt.sh retries, without a network."""

from __future__ import annotations

import asyncio
import json
import unittest

from modules.subdomain import SubdomainEnumerator, extract_subdomains
from utils.validators import parse_target


class ExtractTests(unittest.TestCase):
    def test_filters_wildcards_emails_and_unrelated_names(self) -> None:
        entries = [
            {
                "name_value": "\n".join(
                    [
                        "*.Example.COM",
                        "www.example.com",
                        "user@example.com",
                        "notexample.com",
                        "evil.example.com.attacker.com",
                        "api.example.com",
                        "*.other.com",
                    ]
                )
            }
        ]
        self.assertEqual(
            extract_subdomains(entries, "example.com"),
            ["api.example.com", "example.com", "www.example.com"],
        )

    def test_rejects_non_list_payload(self) -> None:
        with self.assertRaises(ValueError):
            extract_subdomains({"error": "nope"}, "example.com")


class _Content:
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def read(self, n: int = -1) -> bytes:
        if n is None or n < 0 or n >= len(self._data):
            return self._data
        return self._data[:n]


class _Response:
    def __init__(self, status: int, payload: bytes) -> None:
        self.status = status
        self.content = _Content(payload)

    async def __aenter__(self) -> "_Response":
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False


class _Session:
    def __init__(self, responses: list[_Response]) -> None:
        self._responses = list(responses)
        self.calls = 0

    def get(self, *_args: object, **_kwargs: object) -> _Response:
        self.calls += 1
        return self._responses.pop(0)


class RetryTests(unittest.TestCase):
    def test_retries_transient_crtsh_failure(self) -> None:
        payload = json.dumps([{"name_value": "www.example.com"}]).encode()
        session = _Session([_Response(503, b""), _Response(200, payload)])
        enumerator = SubdomainEnumerator(
            parse_target("example.com"),
            session,  # type: ignore[arg-type]
            timeout=5,
            retries=2,
            retry_delay=0,
            module_timeout=10,
        )

        result = asyncio.run(enumerator.run())

        self.assertEqual(session.calls, 2)
        self.assertEqual(result.status, "success")
        self.assertEqual(result.findings, ["www.example.com"])

    def test_ip_target_is_skipped(self) -> None:
        session = _Session([])
        enumerator = SubdomainEnumerator(
            parse_target("127.0.0.1"),
            session,  # type: ignore[arg-type]
            module_timeout=5,
        )
        result = asyncio.run(enumerator.run())
        self.assertEqual(result.status, "skipped")
        self.assertEqual(session.calls, 0)
        self.assertIn("domain name", result.meta["reason"])


if __name__ == "__main__":
    unittest.main()
