"""Asynchronous TCP connect scanner for authorized assessments."""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from modules.base import ReconModule
from utils.constants import MAX_PORT_ERRORS
from utils.models import ParsedTarget

COMMON_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    3306,
    3389,
    8080,
    8443,
)

# A curated set of frequently exposed TCP services. This is a connect scan
# of port numbers only; it does not probe or exploit the service behind them.
TOP_100_PORTS: tuple[int, ...] = (
    20, 21, 22, 23, 25, 53, 80, 81, 88, 110,
    111, 119, 123, 135, 139, 143, 161, 179, 389, 443,
    445, 465, 514, 515, 587, 631, 636, 873, 902, 990,
    993, 995, 1080, 1099, 1194, 1433, 1434, 1521, 1723, 1883,
    2049, 2082, 2083, 2181, 2222, 2375, 2376, 3000, 3128, 3268,
    3269, 3306, 3389, 3690, 4369, 4443, 4444, 5000, 5060, 5432,
    5601, 5672, 5900, 5901, 5984, 5985, 5986, 6379, 6443, 6667,
    7001, 7070, 8000, 8008, 8009, 8080, 8081, 8088, 8161, 8443,
    8880, 8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418,
    9443, 9999, 10000, 10250, 11211, 15672, 27017, 27018, 50000, 61616,
)

SERVICE_NAMES: dict[int, str] = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    81: "HTTP-Alt",
    88: "Kerberos",
    110: "POP3",
    111: "RPCBind",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "Submission",
    631: "IPP",
    636: "LDAPS",
    873: "Rsync",
    902: "VMware",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1099: "RMI",
    1194: "OpenVPN",
    1433: "MSSQL",
    1434: "MSSQL-Browser",
    1521: "Oracle",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2181: "ZooKeeper",
    2222: "SSH-Alt",
    2375: "Docker",
    2376: "Docker-SSL",
    3000: "HTTP-Dev",
    3128: "Squid",
    3268: "LDAP-GC",
    3269: "LDAPS-GC",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4369: "EPMD",
    4443: "HTTPS-Alt",
    5000: "HTTP-Dev",
    5060: "SIP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "AMQP",
    5900: "VNC",
    5901: "VNC-1",
    5984: "CouchDB",
    5985: "WinRM",
    5986: "WinRM-SSL",
    6379: "Redis",
    6443: "Kubernetes",
    6667: "IRC",
    7001: "WebLogic",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8009: "AJP",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8088: "HTTP-Alt",
    8161: "ActiveMQ",
    8443: "HTTPS-Alt",
    8880: "HTTP-Alt",
    8888: "HTTP-Alt",
    9000: "HTTP-Alt",
    9042: "Cassandra",
    9090: "HTTP-Admin",
    9092: "Kafka",
    9100: "JetDirect",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Transport",
    9418: "Git",
    9443: "HTTPS-Alt",
    9999: "HTTP-Alt",
    10000: "Webmin",
    10250: "Kubelet",
    11211: "Memcached",
    15672: "RabbitMQ",
    27017: "MongoDB",
    27018: "MongoDB-Alt",
    50000: "DB2",
    61616: "ActiveMQ-OpenWire",
}


def service_name(port: int) -> str:
    known = SERVICE_NAMES.get(port)
    if known:
        return known
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


class PortScanner(ReconModule):
    """Concurrent TCP connect scan with a hard cap on in-flight sockets."""

    name = "ports"
    label = "Port scan"

    def __init__(
        self,
        target: ParsedTarget,
        *,
        ports: list[int] | None = None,
        timeout: float = 1.5,
        concurrency: int = 100,
        module_timeout: float = 180.0,
        logger: Any = None,
    ) -> None:
        super().__init__(module_timeout=module_timeout, logger=logger)
        selected = list(ports) if ports is not None else list(COMMON_PORTS)
        if target.port is not None and target.port not in selected:
            selected.append(target.port)
        self.ports = sorted(set(selected))
        self.target = target
        self.timeout = timeout
        self.concurrency = concurrency
        self._unexpected: list[str] = []

    @property
    def total_steps(self) -> int | None:
        return len(self.ports)

    async def execute(self) -> tuple[list[Any], dict[str, Any]]:
        addresses = await self._resolve()
        scan_host = addresses[0]
        semaphore = asyncio.Semaphore(self.concurrency)
        self._unexpected = []

        tasks = [
            self._check_port(scan_host, port, semaphore)
            for port in self.ports
        ]
        checked = await asyncio.gather(*tasks)
        open_ports = [item for item in checked if item is not None]
        open_ports.sort(key=lambda item: item["port"])

        if self._unexpected:
            self.logger.warning(
                f"[ports] {len(self._unexpected)} unexpected socket error(s); "
                "see the report for the first few."
            )

        return open_ports, {
            "technique": "tcp-connect",
            "hostname": self.target.host,
            "scanned_address": scan_host,
            "resolved_addresses": addresses,
            "ports_scanned": len(self.ports),
            "port_list": self.ports,
            "open_count": len(open_ports),
            "display_count": len(open_ports),
            "concurrency": self.concurrency,
            "timeout": self.timeout,
            "socket_errors": self._unexpected[:MAX_PORT_ERRORS],
        }

    async def _resolve(self) -> list[str]:
        if self.target.is_ip:
            return [self.target.host]

        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(
                    self.target.host,
                    None,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                ),
                timeout=max(self.timeout, 5.0),
            )
        except TimeoutError as exc:
            raise OSError(f"DNS lookup timed out for {self.target.host}.") from exc
        except socket.gaierror as exc:
            raise OSError(f"Could not resolve {self.target.host}: {exc}") from exc

        addresses: list[str] = []
        for info in infos:
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise OSError(f"Could not resolve {self.target.host}.")
        self.logger.debug(f"[ports] {self.target.host} resolved to {', '.join(addresses)}")
        return addresses

    async def _check_port(
        self,
        host: str,
        port: int,
        semaphore: asyncio.Semaphore,
    ) -> dict[str, Any] | None:
        writer: asyncio.StreamWriter | None = None
        async with semaphore:
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout,
                )
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service_name(port),
                }
            except (TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception as exc:
                if len(self._unexpected) < MAX_PORT_ERRORS:
                    self._unexpected.append(f"{port}: {exc.__class__.__name__}: {exc}")
                return None
            finally:
                self.advance()
                if writer is not None:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
                    except Exception:
                        pass
