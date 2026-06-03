# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""RFC 3339 timestamp validation matching Go ``time.Parse(time.RFC3339Nano, s)``.

Go's RFC3339Nano layout (``2006-01-02T15:04:05.999999999Z07:00``) is strict:

  - ``T`` and ``Z`` are literal uppercase; lowercase is rejected.
  - Date and time fields are fixed-width, zero-padded.
  - Fractional seconds are optional, ``.`` followed by one or more digits (Go
    accepts an arbitrary number of fractional digits, beyond nanosecond).
  - The zone is ``Z`` or ``±HH:MM``.
  - Calendar validity is enforced: month 1-12, the correct day-of-month for the
    month and year (leap years included), hour 0-23, minute 0-59, second 0-59
    (no leap second 60).

Python's ``datetime.fromisoformat`` is too lenient (it accepts a space separator,
lowercase, and other variants), so this module validates with an explicit grammar
plus a calendar check rather than delegating.
"""

from __future__ import annotations

import re

from .number import BadGrammarError

# Anchored grammar: date, 'T', time, optional fractional seconds, zone.
_RFC3339NANO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"  # YYYY-MM-DD
    r"T(\d{2}):(\d{2}):(\d{2})"  # THH:MM:SS
    r"(?:\.(\d+))?"  # optional .fraction (1+ digits)
    r"(Z|[+-]\d{2}:\d{2})$"  # zone: Z or +HH:MM / -HH:MM
)

_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _is_leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def validate_timestamp(s: str) -> None:
    """Validate an RFC 3339 (nanosecond-precision) timestamp with a zone.

    Raises :class:`BadGrammarError` on any deviation from what Go's RFC3339Nano
    layout accepts.
    """
    if s == "":
        raise BadGrammarError("empty timestamp")
    m = _RFC3339NANO_RE.match(s)
    if not m:
        raise BadGrammarError(f"timestamp {s!r} is not RFC3339Nano")
    year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hour, minute, second = int(m.group(4)), int(m.group(5)), int(m.group(6))
    if not 1 <= month <= 12:
        raise BadGrammarError(f"timestamp {s!r}: month out of range")
    max_day = _DAYS_IN_MONTH[month - 1]
    if month == 2 and _is_leap(year):
        max_day = 29
    if not 1 <= day <= max_day:
        raise BadGrammarError(f"timestamp {s!r}: day out of range")
    if hour > 23:
        raise BadGrammarError(f"timestamp {s!r}: hour out of range")
    if minute > 59:
        raise BadGrammarError(f"timestamp {s!r}: minute out of range")
    if second > 59:
        raise BadGrammarError(f"timestamp {s!r}: second out of range")
    zone = m.group(8)
    if zone != "Z":
        # ±HH:MM offset. Go accepts offset hours up to 24 and does not range-check
        # the offset minute (it parses 2 digits and accepts any value), so match
        # that tolerance exactly rather than imposing a stricter 0-59 minute rule.
        off_hour = int(zone[1:3])
        if off_hour > 24:
            raise BadGrammarError(f"timestamp {s!r}: zone offset hour out of range")
