"""
HTTP security headers audit module.
"""

from __future__ import annotations

from typing import Dict, List

import requests

SECURITY_HEADERS: List[str] = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class HTTPAuditor:
    """Audits a target URL's response for common security headers."""

    def __init__(self, url: str, timeout: int = 10) -> None:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        self.url = url
        self.timeout = timeout

    def audit(self) -> Dict[str, str]:
        """
        Fetch the target URL and check for the presence of key
        security-related HTTP response headers.

        Returns:
            A dict mapping each header name to "PRESENT" or "MISSING".
            Includes an "_error" key if the request failed.
        """
        result: Dict[str, str] = {}

        try:
            response = requests.get(
                self.url, timeout=self.timeout, allow_redirects=True
            )
        except requests.exceptions.SSLError:
            return {"_error": f"SSL verification failed for {self.url}"}
        except requests.exceptions.Timeout:
            return {"_error": f"Request timed out for {self.url}"}
        except requests.exceptions.ConnectionError:
            return {"_error": f"Could not connect to {self.url}"}
        except requests.exceptions.RequestException as exc:
            return {"_error": f"Request failed: {exc}"}

        headers = response.headers

        for header_name in SECURITY_HEADERS:
            result[header_name] = "PRESENT" if header_name in headers else "MISSING"

        result["_status_code"] = str(response.status_code)
        result["_final_url"] = response.url

        return result
