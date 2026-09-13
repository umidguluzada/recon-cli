"""
Asynchronous TCP port scanner module.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List

COMMON_PORTS: List[int] = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 8443]

SERVICE_NAMES: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


class PortScanner:
    """Performs asynchronous TCP connect scans against a target host."""

    def __init__(
        self,
        target: str,
        ports: List[int] | None = None,
        timeout: float = 1.5,
        concurrency: int = 100,
    ) -> None:
        self.target = target
        self.ports = ports if ports is not None else COMMON_PORTS
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def _check_port(self, port: int) -> Dict[str, str] | None:
        """Attempt a TCP connection to a single port with a timeout."""
        async with self.semaphore:
            try:
                conn = asyncio.open_connection(self.target, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return {
                    "port": port,
                    "state": "OPEN",
                    "service": SERVICE_NAMES.get(port, "unknown"),
                }
            except asyncio.TimeoutError:
                return None
            except ConnectionRefusedError:
                return None
            except OSError:
                return None
            except Exception as exc:
                print(f"[!] Unexpected error scanning port {port}: {exc}")
                return None

    async def scan(self) -> List[Dict[str, str]]:
        """
        Scan all configured ports concurrently.

        Returns:
            A list of dicts describing each open port found.
        """
        tasks = [self._check_port(port) for port in self.ports]
        results = await asyncio.gather(*tasks)
        open_ports = [r for r in results if r is not None]
        return sorted(open_ports, key=lambda r: r["port"])

    def run(self) -> List[Dict[str, str]]:
        """Synchronous wrapper to run the async scan from non-async code."""
        return asyncio.run(self.scan())

    @staticmethod
    def resolve_target(hostname_or_ip: str) -> str:
        """Return the target as-is; kept as a hook for future DNS resolution logic."""
        return hostname_or_ip
