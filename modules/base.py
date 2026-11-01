"""Base class that isolates failures and enforces a module timeout."""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from utils.console import ScanLogger
from utils.models import ModuleResult


class ReconModule(ABC):
    """A scan that can fail without stopping the rest of the run."""

    name: str = "module"
    label: str = "Module"

    def __init__(
        self,
        *,
        module_timeout: float = 180.0,
        logger: ScanLogger | None = None,
    ) -> None:
        self.module_timeout = module_timeout
        self.logger = logger or ScanLogger()
        self.errors: list[str] = []
        self._on_advance: Callable[[int], None] = lambda _steps=1: None

    @property
    def total_steps(self) -> int | None:
        """Progress total. None means the task is indeterminate."""
        return None

    def advance(self, steps: int = 1) -> None:
        self._on_advance(steps)

    @abstractmethod
    async def execute(self) -> tuple[list[Any], dict[str, Any]]:
        """Return findings and metadata, or raise on a fatal module error."""

    async def run(
        self,
        *,
        on_advance: Callable[[int], None] | None = None,
    ) -> ModuleResult:
        self._on_advance = on_advance or (lambda _steps=1: None)
        self.errors = []
        started = datetime.now(timezone.utc)
        clock = time.perf_counter()
        findings: list[Any] = []
        meta: dict[str, Any] = {}
        status = "success"

        try:
            findings, meta = await asyncio.wait_for(
                self.execute(),
                timeout=self.module_timeout,
            )
            if meta.get("skipped"):
                status = "skipped"
            elif self.errors and findings:
                status = "partial"
            elif self.errors:
                status = "error"
        except TimeoutError:
            status = "error"
            self.errors.append(f"Module timed out after {self.module_timeout:.1f}s.")
            self.logger.error(f"[{self.name}] timed out after {self.module_timeout:.1f}s.")
        except Exception as exc:
            status = "error"
            self.errors.append(f"{exc.__class__.__name__}: {exc}")
            self.logger.error(f"[{self.name}] {exc.__class__.__name__}: {exc}")

        duration_ms = round((time.perf_counter() - clock) * 1000, 2)
        return ModuleResult(
            name=self.name,
            label=self.label,
            status=status,
            started_at=started.isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=duration_ms,
            findings=findings,
            errors=list(self.errors),
            meta=meta,
        )
