#!/usr/bin/env python3
"""Mirror `go test -json` to a file while printing live package completions."""

from __future__ import annotations

import argparse
import json
import sys


def format_duration(seconds: float) -> str:
    if seconds >= 60:
        minutes, remainder = divmod(seconds, 60)
        return f"{int(minutes)}m{remainder:04.1f}s"
    return f"{seconds:.1f}s"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stream package completions from go test -json while saving raw JSON."
    )
    parser.add_argument("--json-out", required=True, help="path to write raw go test JSON")
    parser.add_argument("--label", default="go test", help="label printed in progress lines")
    args = parser.parse_args()

    with open(args.json_out, "w", encoding="utf-8") as raw:
        for line in sys.stdin:
            raw.write(line)
            raw.flush()

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

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
                f"[{args.label}] {action:<4} {format_duration(float(elapsed)):>8} {package}",
                flush=True,
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
