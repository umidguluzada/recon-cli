"""Shared constants for recon-cli."""

from __future__ import annotations

TOOL_NAME = "recon-cli"
VERSION = "2.0.0"
SCHEMA_VERSION = 2
USER_AGENT = f"{TOOL_NAME}/{VERSION} (authorized security assessment)"

DEFAULT_PORT_TIMEOUT = 1.5
DEFAULT_HTTP_TIMEOUT = 20.0
DEFAULT_MODULE_TIMEOUT = 180.0
DEFAULT_CONCURRENCY = 100
DEFAULT_RETRIES = 3
DEFAULT_RETRY_DELAY = 2.0

MAX_CONCURRENCY = 1000
MAX_PORTS = 2048
MAX_HTTP_BODY_BYTES = 20 * 1024 * 1024
MAX_TABLE_ROWS = 200
MAX_PORT_ERRORS = 8

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
