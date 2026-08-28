#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Mirror `go test -json` to a file while printing live package completions."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable, Iterable
from typing import TextIO


def format_duration(seconds: float) -> str:
    if seconds >= 60:
        minutes, remainder = divmod(seconds, 60)
        return f"{int(minutes)}m{remainder:04.1f}s"
    return f"{seconds:.1f}s"


def stream_events(
    lines: Iterable[str],
    *,
    raw: TextIO,
    label: str,
    out: TextIO,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    started = clock()
    first_event_at: float | None = None
    last_event_at: float | None = None

    for line in lines:
        raw.write(line)
        raw.flush()

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        observed_at = clock()
        if first_event_at is None:
            first_event_at = observed_at
        last_event_at = observed_at

        if event.get("Test"):
            continue

        action = event.get("Action")
        package = event.get("Package")
        if action not in {"pass", "fail", "skip"} or not isinstance(package, str):
            continue

        elapsed = event.get("Elapsed", 0.0)
        if not isinstance(elapsed, (int, float)):
            elapsed = 0.0

        print(
            f"[{label}] {action:<4} {format_duration(float(elapsed)):>8} {package}",
            file=out,
            flush=True,
        )

    finished = clock()
    lead = 0.0 if first_event_at is None else first_event_at - started
    span = 0.0 if last_event_at is None else last_event_at - first_event_at
    trailing = 0.0 if last_event_at is None else finished - last_event_at
    print(
        f"[{label}] first JSON lead: {format_duration(lead)}; "
        f"JSON stream span: {format_duration(span)}; "
        f"post-stream tail: {format_duration(trailing)}",
        file=out,
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stream package completions from go test -json while saving raw JSON."
    )
    parser.add_argument("--json-out", required=True, help="path to write raw go test JSON")
    parser.add_argument("--label", default="go test", help="label printed in progress lines")
    args = parser.parse_args()

    with open(args.json_out, "w", encoding="utf-8") as raw:
        stream_events(sys.stdin, raw=raw, label=args.label, out=sys.stdout)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
