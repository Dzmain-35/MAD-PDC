"""
DateTime Utilities for MAD-PDC
Provides centralized date/time handling to support VM snapshot date override.

When analysts work in Virtual Machines and revert to snapshots, the system clock
may be incorrect (set to the snapshot date). This module provides a single point
of control for all date/time operations so the correct date can be enforced
regardless of the system clock.

Usage:
    from datetime_utils import get_current_datetime

    # Instead of datetime.now(), use:
    now = get_current_datetime()
"""

from datetime import datetime, timedelta
from typing import Optional
import threading


class _DateTimeManager:
    """
    Internal singleton managing the date/time override state.

    When a date override is active, get_current_datetime() returns the overridden
    date with the current system time-of-day offset applied, so timestamps within
    a session still progress naturally.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._override_date: Optional[datetime] = None
        self._override_set_at: Optional[datetime] = None  # system time when override was set

    def set_date_override(self, target_date: datetime) -> None:
        """
        Set a date override. All subsequent calls to get_current_datetime()
        will return timestamps on the target date, with time-of-day advancing
        naturally from the moment the override is set.

        Args:
            target_date: The correct date to use (only the date portion is used).
        """
        with self._lock:
            self._override_date = target_date.replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            self._override_set_at = datetime.now()

    def clear_date_override(self) -> None:
        """Remove the date override and revert to system clock."""
        with self._lock:
            self._override_date = None
            self._override_set_at = None

    def get_current_datetime(self) -> datetime:
        """
        Return the current datetime, applying the date override if active.

        If an override is set, the returned datetime uses the overridden date
        but the time-of-day advances normally from when the override was set.
        """
        with self._lock:
            if self._override_date is not None and self._override_set_at is not None:
                system_now = datetime.now()
                elapsed = system_now - self._override_set_at
                return self._override_date + timedelta(
                    hours=self._override_set_at.hour,
                    minutes=self._override_set_at.minute,
                    seconds=self._override_set_at.second,
                    microseconds=self._override_set_at.microsecond,
                ) + elapsed
            return datetime.now()

    def has_override(self) -> bool:
        """Check if a date override is currently active."""
        with self._lock:
            return self._override_date is not None

    def get_override_date(self) -> Optional[datetime]:
        """Return the override date if set, else None."""
        with self._lock:
            return self._override_date


# Module-level singleton
_manager = _DateTimeManager()


def get_current_datetime() -> datetime:
    """
    Get the current datetime, respecting any VM snapshot date override.

    Drop-in replacement for datetime.now() throughout the MAD-PDC codebase.
    """
    return _manager.get_current_datetime()


def set_date_override(target_date: datetime) -> None:
    """
    Override the application date (for VM snapshot recovery).

    Args:
        target_date: The correct date to use.
    """
    _manager.set_date_override(target_date)


def clear_date_override() -> None:
    """Remove the date override and revert to the system clock."""
    _manager.clear_date_override()


def has_date_override() -> bool:
    """Check whether a date override is currently active."""
    return _manager.has_override()


def get_override_date() -> Optional[datetime]:
    """Return the override date if set, else None."""
    return _manager.get_override_date()
