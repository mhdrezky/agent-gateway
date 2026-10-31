from datetime import UTC, datetime, timedelta

DEFAULT_START = datetime(2026, 1, 1, tzinfo=UTC)


class FixedClock:
    """A clock that only moves when told to."""

    def __init__(self, start: datetime = DEFAULT_START) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta
