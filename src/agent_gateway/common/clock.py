"""UTC time helpers. All timestamps in the gateway are timezone-aware UTC."""

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_rfc3339(value: datetime) -> str:
    """Format as RFC 3339 with millisecond precision and a ``Z`` suffix."""
    if value.tzinfo is None:
        raise ValueError("naive datetimes are not allowed")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
