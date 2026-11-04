"""UTC timestamp utilities for KASEVRA records."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(UTC)


def format_utc(value: datetime | None = None) -> str:
    """Format a datetime as an ISO 8601 UTC timestamp ending in Z."""
    timestamp = value if value is not None else utc_now()

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")

    return (
        timestamp.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    )
