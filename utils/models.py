"""Result objects shared by scanners and the reporting engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ModuleResult:
    """Outcome of a single reconnaissance module."""

    name: str
    label: str
    status: str
    started_at: str
    finished_at: str
    duration_ms: float
    findings: list[Any] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def display_count(self) -> int:
        value = self.meta.get("display_count")
        if isinstance(value, int):
            return value
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["display_count"] = self.display_count
        return payload


@dataclass(frozen=True)
class ParsedTarget:
    """Normalized scan target derived from the CLI argument."""

    raw: str
    host: str
    port: int | None
    scheme: str | None
    path: str
    url: str
    is_ip: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
