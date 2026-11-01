"""Passive subdomain enumeration via Certificate Transparency logs."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import aiohttp

from modules.base import ReconModule
from utils.constants import MAX_HTTP_BODY_BYTES
from utils.models import ParsedTarget
from utils.validators import belongs_to_domain, is_subdomain_name, normalize_host

CRT_SH_URL = "https://crt.sh/"


def extract_subdomains(entries: Any, domain: str) -> list[str]:
    """Pull unique child names out of a crt.sh JSON payload."""
    if not isinstance(entries, list):
        raise ValueError("crt.sh response was not a JSON array.")

    found: set[str] = set()
    apex = normalize_host(domain)
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value", "")
        if not isinstance(name_value, str):
            continue
        for line in name_value.replace("\r", "\n").split("\n"):
            candidate = line.strip().lower().rstrip(".")
            if not candidate or "@" in candidate or " " in candidate:
                continue
            if candidate.startswith("*."):
                candidate = candidate[2:]
            if "*" in candidate:
                continue
            try:
                candidate = normalize_host(candidate)
            except ValueError:
                continue
            if not is_subdomain_name(candidate):
                continue
            if belongs_to_domain(candidate, apex):
                found.add(candidate)
    return sorted(found)


class SubdomainEnumerator(ReconModule):
    """Queries crt.sh and returns validated names for one domain."""

    name = "subdomains"
    label = "Subdomains"

    def __init__(
        self,
        target: ParsedTarget,
        session: aiohttp.ClientSession,
        *,
        timeout: float = 20.0,
        retries: int = 3,
        retry_delay: float = 2.0,
        module_timeout: float = 180.0,
        logger: Any = None,
    ) -> None:
        super().__init__(module_timeout=module_timeout, logger=logger)
        self.target = target
        self.session = session
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay

    async def execute(self) -> tuple[list[Any], dict[str, Any]]:
        if self.target.is_ip:
            reason = "Subdomain enumeration requires a domain name, not an IP address."
            return [], {
                "source": "crt.sh",
                "skipped": True,
                "reason": reason,
                "display_count": 0,
            }

        domain = self.target.host
        query = f"%.{domain}"
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        last_status: int | None = None

        for attempt in range(1, self.retries + 1):
            try:
                payload = await self._fetch(query, timeout)
                names = extract_subdomains(payload, domain)
                return names, {
                    "source": "crt.sh",
                    "query": query,
                    "attempts": attempt,
                    "certificates": len(payload) if isinstance(payload, list) else 0,
                    "display_count": len(names),
                }
            except _TransientError as exc:
                last_status = exc.status
                self.logger.warning(
                    f"[subdomains] crt.sh unavailable ({exc}), "
                    f"attempt {attempt}/{self.retries}."
                )
            except aiohttp.ClientError as exc:
                last_status = None
                self.logger.warning(
                    f"[subdomains] connection error ({exc.__class__.__name__}), "
                    f"attempt {attempt}/{self.retries}."
                )
            except TimeoutError:
                self.logger.warning(
                    f"[subdomains] crt.sh timed out, attempt {attempt}/{self.retries}."
                )
            except ValueError as exc:
                self.errors.append(str(exc))
                return [], {
                    "source": "crt.sh",
                    "query": query,
                    "attempts": attempt,
                    "display_count": 0,
                }

            if attempt < self.retries:
                await asyncio.sleep(self.retry_delay * attempt)

        self.errors.append(
            f"crt.sh did not return a usable result after {self.retries} attempts."
        )
        return [], {
            "source": "crt.sh",
            "query": query,
            "attempts": self.retries,
            "last_status": last_status,
            "display_count": 0,
        }

    async def _fetch(self, query: str, timeout: aiohttp.ClientTimeout) -> Any:
        async with self.session.get(
            CRT_SH_URL,
            params={"q": query, "output": "json"},
            timeout=timeout,
        ) as response:
            if response.status in {429, 500, 502, 503, 504}:
                raise _TransientError(response.status)
            if response.status >= 400:
                raise ValueError(f"crt.sh returned HTTP {response.status}.")

            raw = await response.content.read(MAX_HTTP_BODY_BYTES + 1)
            if len(raw) > MAX_HTTP_BODY_BYTES:
                raise ValueError("crt.sh response exceeded the 20 MB response limit.")
            if not raw.strip():
                raise _TransientError(response.status or 204)

            try:
                payload = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as exc:
                raise _TransientError(response.status) from exc
            if not isinstance(payload, list):
                raise _TransientError(response.status)
            return payload


class _TransientError(Exception):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"HTTP {status}" if status else "empty response")
