"""Target and port-list validation."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from utils.constants import MAX_PORTS
from utils.models import ParsedTarget

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
# Certificate logs often contain underscore labels (for example DKIM names).
_SUBDOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$"
)


def normalize_host(value: str) -> str:
    """Lower-case a host, canonicalize IP addresses, and punycode Unicode names."""
    host = value.strip().lower().rstrip(".")
    if not host:
        raise ValueError("Host name is empty.")
    if is_ip_address(host):
        return str(ipaddress.ip_address(host))
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid host name: {value}") from exc


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_hostname(value: str) -> bool:
    return _HOSTNAME_RE.fullmatch(value) is not None


def is_subdomain_name(value: str) -> bool:
    return _SUBDOMAIN_RE.fullmatch(value) is not None or is_hostname(value)


def _format_host(host: str, is_ip: bool) -> str:
    if is_ip and ":" in host:
        return f"[{host}]"
    return host


def parse_target(raw: str) -> ParsedTarget:
    """
    Parse a host, host:port, or http(s) URL into a scan target.

    Credentials, query strings, and fragments are rejected so the tool
    only ever scans the origin the operator named.
    """
    value = raw.strip()
    if not value or any(character.isspace() for character in value):
        raise ValueError("Target must be a hostname, IP address, or http(s) URL without spaces.")

    scheme: str | None = None
    path = ""
    port: int | None = None

    if "://" in value:
        parsed = urlparse(value)
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            raise ValueError("Only http and https URLs are supported.")
        if parsed.username or parsed.password:
            raise ValueError("Credentials in the target URL are not supported.")
        if parsed.query or parsed.fragment:
            raise ValueError("Remove the query string and fragment. Pass a host or origin.")
        if not parsed.hostname:
            raise ValueError(f"Could not parse a host from {raw!r}.")
        host = normalize_host(parsed.hostname)
        port = parsed.port
        path = parsed.path or ""
        if path and (not path.startswith("/") or "\\" in path or ".." in path.split("/")):
            raise ValueError("The URL path must be absolute and must not contain '..'.")
    else:
        host, port = _split_host_port(value)
        host = normalize_host(host)

    is_ip = is_ip_address(host)
    if not is_ip and not is_hostname(host):
        raise ValueError(f"Invalid target: {raw}")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")

    display = _format_host(host, is_ip)
    if port is not None:
        display = f"{display}:{port}"
    if scheme is None:
        url = f"https://{display}"
    else:
        url = f"{scheme}://{display}{path}"

    return ParsedTarget(
        raw=raw.strip(),
        host=host,
        port=port,
        scheme=scheme,
        path=path,
        url=url,
        is_ip=is_ip,
    )


def _split_host_port(value: str) -> tuple[str, int | None]:
    if value.startswith("["):
        if "]" not in value:
            raise ValueError(f"Invalid IPv6 target: {value}")
        host, _, rest = value[1:].partition("]")
        if not rest:
            return host, None
        if not rest.startswith(":"):
            raise ValueError(f"Invalid IPv6 target: {value}")
        port_text = rest[1:]
        if not port_text.isdigit():
            raise ValueError(f"Invalid port: {port_text}")
        return host, int(port_text)

    if value.count(":") > 1:
        return value, None

    if ":" in value:
        host, port_text = value.rsplit(":", 1)
        if port_text.isdigit():
            return host, int(port_text)
    return value, None


def parse_ports(spec: str, *, limit: int = MAX_PORTS) -> list[int]:
    """Parse '80,443,8000-8002' into a sorted unique port list."""
    if not spec or not spec.strip():
        raise ValueError("Port list is empty.")

    ports: set[int] = set()
    for part in spec.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise ValueError(f"Invalid port range: {token}")
            start, end = int(start_text), int(end_text)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {token}")
            width = end - start + 1
            if width > limit or len(ports) + width > limit:
                raise ValueError(f"A single scan is limited to {limit} ports.")
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid port: {token}")
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError(f"Port out of range: {port}")
            ports.add(port)
            if len(ports) > limit:
                raise ValueError(f"A single scan is limited to {limit} ports.")

    if not ports:
        raise ValueError("Port list is empty.")
    return sorted(ports)


def belongs_to_domain(candidate: str, domain: str) -> bool:
    """True when candidate is the domain itself or a real subdomain of it."""
    if candidate == domain:
        return True
    return candidate.endswith(f".{domain}")
