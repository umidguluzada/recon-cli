"""Small display helpers shared by the terminal and HTML reports."""

from __future__ import annotations

NOTICE = (
    "Run only against systems you are authorized to test. "
    "Confirm each finding before you treat it as a vulnerability."
)


def format_duration(duration_ms: float) -> str:
    if duration_ms < 1000:
        return f"{duration_ms:.0f} ms"
    return f"{duration_ms / 1000:.2f} s"
