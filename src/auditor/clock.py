"""Injectable clock seam for deterministic time-dependent logic.

Production call sites may still use ``datetime.now``; tests and fixtures that
need stable time should accept a :class:`Clock` (or call :func:`get_clock`).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """Source of the current UTC instant."""

    def now(self) -> datetime:
        """Return a timezone-aware UTC datetime."""
        ...


@dataclass(frozen=True, slots=True)
class SystemClock:
    """Wall-clock UTC time (production default)."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class FixedClock:
    """Clock that always returns a predetermined UTC instant."""

    instant: datetime

    def now(self) -> datetime:
        instant = self.instant
        if instant.tzinfo is None:
            return instant.replace(tzinfo=timezone.utc)
        return instant.astimezone(timezone.utc)


_CLOCK: Clock = SystemClock()


def get_clock() -> Clock:
    """Return the process-wide clock (defaults to :class:`SystemClock`)."""
    return _CLOCK


def set_clock(clock: Clock | None) -> Clock:
    """Install ``clock`` (or restore :class:`SystemClock` when ``None``).

    Returns the previous clock for nested test fixtures.
    """
    global _CLOCK
    previous = _CLOCK
    _CLOCK = clock if clock is not None else SystemClock()
    return previous
