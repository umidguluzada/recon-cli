"""
Subdomain enumeration module using Certificate Transparency logs (crt.sh).
"""

from __future__ import annotations

import json
import re
import time
from typing import List, Set

import requests

# Valid hostname label: letters, digits, hyphens (no leading/trailing hyphen)
_HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
)


class SubdomainEnumerator:
    """Enumerates subdomains for a given domain via crt.sh CT log search."""

    CRT_SH_URL = "https://crt.sh/"

    def __init__(
        self,
        domain: str,
        timeout: int = 15,
        max_retries: int = 3,
        retry_delay: float = 3.0,
    ) -> None:
        self.domain = domain.strip().lower()
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def _is_valid_subdomain(self, candidate: str) -> bool:
        """
        Validate that a candidate string is a proper subdomain of
        self.domain — not an email, CA metadata string, or a
        different domain that merely shares a suffix substring.
        """
        if "@" in candidate or " " in candidate:
            return False

        if not _HOSTNAME_RE.match(candidate):
            return False

        if candidate == self.domain:
            return True

        # Must end with ".<domain>" (proper label boundary), not just
        # a raw substring match like "testexample.com".endswith("example.com")
        return candidate.endswith(f".{self.domain}")

    def enumerate(self) -> List[str]:
        """
        Query crt.sh for certificates matching the domain and extract
        unique, valid subdomains. Retries on transient server-side
        errors (crt.sh is frequently overloaded).

        Returns:
            A sorted list of unique subdomains (excluding wildcards,
            emails, and unrelated domains).
        """
        params = {"q": f"%.{self.domain}", "output": "json"}
        subdomains: Set[str] = set()

        response = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.get(
                    self.CRT_SH_URL, params=params, timeout=self.timeout
                )
                response.raise_for_status()
                break
            except requests.exceptions.Timeout:
                print(
                    f"[!] crt.sh request timed out (attempt {attempt}/{self.max_retries})"
                )
            except requests.exceptions.ConnectionError:
                print(
                    f"[!] Connection error reaching crt.sh (attempt {attempt}/{self.max_retries})"
                )
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status in (502, 503, 504):
                    print(
                        f"[!] crt.sh temporarily unavailable ({status}), "
                        f"retrying (attempt {attempt}/{self.max_retries})..."
                    )
                else:
                    print(f"[!] HTTP error from crt.sh: {exc}")
                    return []
            except requests.exceptions.RequestException as exc:
                print(f"[!] Unexpected request error: {exc}")
                return []

            if attempt < self.max_retries:
                time.sleep(self.retry_delay * attempt)

        if response is None or response.status_code != 200:
            print(
                f"[!] Failed to reach crt.sh after {self.max_retries} attempts. "
                "The service may be overloaded — try again in a minute."
            )
            return []

        try:
            data = response.json()
        except json.JSONDecodeError:
            print("[!] Failed to parse crt.sh response as JSON (empty or malformed).")
            return []

        for entry in data:
            name_value = entry.get("name_value", "")
            for line in name_value.split("\n"):
                candidate = line.strip().lower()
                if not candidate:
                    continue
                if candidate.startswith("*."):
                    candidate = candidate[2:]
                if self._is_valid_subdomain(candidate):
                    subdomains.add(candidate)

        return sorted(subdomains)
