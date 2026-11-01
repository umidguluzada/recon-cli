"""HTTP security-header audit."""

from __future__ import annotations

import re
import ssl
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

import aiohttp

from modules.base import ReconModule
from utils.models import ParsedTarget

_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_VALUE_LIMIT = 240

HEADER_CHECKS: tuple[dict[str, Any], ...] = (
    {
        "name": "Strict-Transport-Security",
        "severity": "high",
        "https_only": True,
        "recommendation": (
            "Send Strict-Transport-Security with a long max-age on HTTPS "
            "responses so browsers stay on HTTPS."
        ),
    },
    {
        "name": "Content-Security-Policy",
        "severity": "medium",
        "https_only": False,
        "recommendation": (
            "Publish a Content-Security-Policy that limits script, frame, and "
            "object sources to origins you control."
        ),
    },
    {
        "name": "X-Frame-Options",
        "severity": "medium",
        "https_only": False,
        "recommendation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN, or use a CSP "
            "frame-ancestors directive, to reduce clickjacking risk."
        ),
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "https_only": False,
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    {
        "name": "Referrer-Policy",
        "severity": "low",
        "https_only": False,
        "recommendation": (
            "Set Referrer-Policy (for example strict-origin-when-cross-origin) "
            "so URLs are not leaked in full to other sites."
        ),
    },
    {
        "name": "Permissions-Policy",
        "severity": "info",
        "https_only": False,
        "recommendation": (
            "Set Permissions-Policy to disable browser features this origin "
            "does not need."
        ),
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "severity": "info",
        "https_only": False,
        "recommendation": (
            "Consider Cross-Origin-Opener-Policy: same-origin to isolate the "
            "browsing context."
        ),
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "severity": "info",
        "https_only": False,
        "recommendation": (
            "Consider Cross-Origin-Resource-Policy so other sites cannot "
            "embed this response unexpectedly."
        ),
    },
)

DISCLOSURE_HEADERS: tuple[str, ...] = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
)

_VALID_FRAME_OPTIONS = {"deny", "sameorigin"}


def _truncate(value: str) -> str:
    text = " ".join(value.split())
    if len(text) <= _VALUE_LIMIT:
        return text
    return text[: _VALUE_LIMIT - 1] + "…"


def _lookup(headers: Mapping[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def _weakness(name: str, value: str, headers: Mapping[str, str]) -> str | None:
    """Return a short reason when a present header is ineffective."""
    lowered = value.strip().lower()
    if not lowered:
        return "The header is present but empty."

    if name == "Strict-Transport-Security":
        match = _MAX_AGE_RE.search(value)
        if match is None:
            return "max-age is missing, so browsers will ignore the policy."
        if int(match.group(1)) < 10800:
            return "max-age is under three hours, so the policy expires very quickly."
        return None

    if name == "Content-Security-Policy":
        if "unsafe-inline" in lowered and "unsafe-eval" in lowered:
            return "The policy allows both unsafe-inline and unsafe-eval."
        return None

    if name == "X-Frame-Options":
        token = lowered.split(";", 1)[0].strip()
        if token in _VALID_FRAME_OPTIONS:
            return None
        csp = _lookup(headers, "Content-Security-Policy") or ""
        if "frame-ancestors" in csp.lower():
            return None
        return "The value is not DENY or SAMEORIGIN."

    if name == "X-Content-Type-Options" and lowered != "nosniff":
        return "The value is not nosniff."

    return None


def evaluate_headers(
    headers: Mapping[str, str],
    *,
    final_url: str,
) -> list[dict[str, Any]]:
    """Classify security headers and version-disclosure headers."""
    scheme = urlparse(final_url).scheme.lower()
    findings: list[dict[str, Any]] = []

    for check in HEADER_CHECKS:
        name = str(check["name"])
        raw_value = _lookup(headers, name)
        base_severity = str(check["severity"])
        recommendation = str(check["recommendation"])

        if check["https_only"] and scheme != "https":
            findings.append(
                {
                    "name": name,
                    "category": "security_header",
                    "status": "not_applicable",
                    "severity": "info",
                    "value": _truncate(raw_value) if raw_value else None,
                    "detail": "This header is evaluated on HTTPS responses.",
                    "recommendation": recommendation,
                }
            )
            continue

        if raw_value is None:
            findings.append(
                {
                    "name": name,
                    "category": "security_header",
                    "status": "missing",
                    "severity": base_severity,
                    "value": None,
                    "detail": "Header was not present on the final response.",
                    "recommendation": recommendation,
                }
            )
            continue

        reason = _weakness(name, raw_value, headers)
        if reason:
            severity = "low" if base_severity == "info" else base_severity
            findings.append(
                {
                    "name": name,
                    "category": "security_header",
                    "status": "weak",
                    "severity": severity,
                    "value": _truncate(raw_value),
                    "detail": reason,
                    "recommendation": recommendation,
                }
            )
            continue

        findings.append(
            {
                "name": name,
                "category": "security_header",
                "status": "present",
                "severity": "info",
                "value": _truncate(raw_value),
                "detail": "Header is present.",
                "recommendation": recommendation,
            }
        )

    csp = _lookup(headers, "Content-Security-Policy") or ""
    frame = _lookup(headers, "X-Frame-Options")
    if frame is None and "frame-ancestors" in csp.lower():
        for finding in findings:
            if finding["name"] == "X-Frame-Options" and finding["status"] == "missing":
                finding["status"] = "present"
                finding["severity"] = "info"
                finding["detail"] = "CSP frame-ancestors covers this control."
                finding["value"] = "frame-ancestors (via Content-Security-Policy)"

    for name in DISCLOSURE_HEADERS:
        raw_value = _lookup(headers, name)
        if not raw_value:
            continue
        findings.append(
            {
                "name": name,
                "category": "information_disclosure",
                "status": "present",
                "severity": "info",
                "value": _truncate(raw_value),
                "detail": "Response advertises a server or framework identifier.",
                "recommendation": "Remove precise product versions from public responses, or return a generic value.",
            }
        )

    xss = _lookup(headers, "X-XSS-Protection")
    if xss is not None:
        findings.append(
            {
                "name": "X-XSS-Protection",
                "category": "security_header",
                "status": "present",
                "severity": "info",
                "value": _truncate(xss),
                "detail": "This header is deprecated. A Content-Security-Policy is the current control.",
                "recommendation": "Prefer Content-Security-Policy over X-XSS-Protection.",
            }
        )

    return findings


def issue_count(findings: list[dict[str, Any]]) -> int:
    return sum(
        1
        for finding in findings
        if finding.get("status") in {"missing", "weak"}
        and finding.get("severity") in {"low", "medium", "high", "critical"}
    )


class HTTPAuditor(ReconModule):
    """Fetches one origin and evaluates the security headers on the final response."""

    name = "headers"
    label = "Header audit"

    def __init__(
        self,
        target: ParsedTarget,
        session: aiohttp.ClientSession,
        *,
        timeout: float = 20.0,
        insecure: bool = False,
        module_timeout: float = 180.0,
        logger: Any = None,
    ) -> None:
        super().__init__(module_timeout=module_timeout, logger=logger)
        self.target = target
        self.session = session
        self.timeout = timeout
        self.insecure = insecure

    async def execute(self) -> tuple[list[Any], dict[str, Any]]:
        candidates = [self.target.url]
        if self.target.scheme is None:
            fallback = "http://" + self.target.url.removeprefix("https://")
            candidates.append(fallback)

        last_error = "Request failed."
        for index, url in enumerate(candidates):
            try:
                fetched = await self._fetch(url)
                findings = evaluate_headers(
                    fetched["headers"],
                    final_url=fetched["final_url"],
                )
                issues = issue_count(findings)
                if index > 0:
                    self.logger.info(f"[headers] HTTPS was unreachable; audited {url} instead.")
                return findings, {
                    "requested_url": url,
                    "final_url": fetched["final_url"],
                    "status_code": fetched["status_code"],
                    "redirects": fetched["redirects"],
                    "https": urlparse(fetched["final_url"]).scheme == "https",
                    "display_count": issues,
                    "issue_count": issues,
                    "checks": len(findings),
                }
            except _FetchError as exc:
                last_error = str(exc)
                self.logger.warning(f"[headers] {exc}")

        self.errors.append(last_error)
        return [], {
            "requested_url": self.target.url,
            "display_count": 0,
            "issue_count": 0,
        }

    async def _fetch(self, url: str) -> dict[str, Any]:
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        ssl_option: bool | ssl.SSLContext = False if self.insecure else True
        try:
            async with self.session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                max_redirects=5,
                ssl=ssl_option,
            ) as response:
                # Touch the body so the connection can be released, but do not
                # store it. Header audits only need the response metadata.
                await response.content.read(65_536)
                redirects = [str(item.url) for item in response.history]
                return {
                    "status_code": response.status,
                    "final_url": str(response.url),
                    "redirects": redirects,
                    "headers": {key: value for key, value in response.headers.items()},
                }
        except TimeoutError as exc:
            raise _FetchError(f"Request timed out for {url}.") from exc
        except aiohttp.ClientSSLError as exc:
            raise _FetchError(f"TLS verification failed for {url}: {exc}") from exc
        except aiohttp.ClientResponseError as exc:
            raise _FetchError(f"HTTP error for {url}: {exc.status} {exc.message}") from exc
        except aiohttp.ClientError as exc:
            raise _FetchError(f"Could not connect to {url}: {exc.__class__.__name__}.") from exc


class _FetchError(Exception):
    pass
