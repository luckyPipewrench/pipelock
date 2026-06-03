# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""RFC3339Nano timestamp grammar parity with Go time.Parse(time.RFC3339Nano)."""

from __future__ import annotations

import pytest

from pipelock_aarp_verify.number import BadGrammarError
from pipelock_aarp_verify.timestamp import validate_timestamp

# (input, accepted-by-Go) pairs gathered from the Go reference.
ACCEPTED = [
    "2026-04-15T12:00:00.000000000Z",
    "2026-04-15T12:00:00Z",
    "2026-04-15T12:00:00.5Z",
    "2026-04-15T12:00:00+05:00",
    "2026-04-15T12:00:00.123-08:00",
    "2026-04-15T12:00:00.123456789012Z",
    "2026-04-15T12:00:00.1234567890123456789Z",
    "2026-04-15T12:00:00-00:00",
    "2026-04-15T12:00:00+24:00",
    "2026-04-15T12:00:00+12:60",
]

REJECTED = [
    "",
    "2026-04-15 12:00:00Z",  # space separator
    "2026-04-15T12:00:00",  # no zone
    "2026-13-15T12:00:00Z",  # month out of range
    "2026-04-15T25:00:00Z",  # hour out of range
    "2026-04-15T12:00:00z",  # lowercase z
    "2026-04-31T12:00:00Z",  # day out of range (April)
    "2026-02-30T12:00:00Z",  # day out of range (Feb)
    "2026-04-15T12:00:60Z",  # second 60 (no leap)
    "2026-04-15T12:00:00.Z",  # dot with no fraction
    "2026-04-15T12:00:00+5:00",  # offset hour not 2-digit
    "2026-04-15T12:00:00+0500",  # offset missing colon
    "2026-4-15T12:00:00Z",  # month not zero-padded
    "2026-04-15T12:00:00+99:00",  # offset hour out of range
    "2026-04-15T12:00:60.0Z",  # second out of range with fraction
    "2026-04-15T12:60:00Z",  # minute out of range
]


@pytest.mark.parametrize("ts", ACCEPTED)
def test_accepted(ts: str):
    validate_timestamp(ts)  # must not raise


@pytest.mark.parametrize("ts", REJECTED)
def test_rejected(ts: str):
    with pytest.raises(BadGrammarError):
        validate_timestamp(ts)


def test_leap_year_feb_29_ok():
    validate_timestamp("2024-02-29T00:00:00Z")


def test_non_leap_year_feb_29_rejected():
    with pytest.raises(BadGrammarError):
        validate_timestamp("2026-02-29T00:00:00Z")
