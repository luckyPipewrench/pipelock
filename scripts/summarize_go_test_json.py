#!/usr/bin/env python3
"""Print a compact package timing summary from `go test -json` output."""

from __future__ import annotations

import argparse
import collections
import json
import sys
from dataclasses import dataclass, field


FAILED_OUTPUT_LIMIT = 80


@dataclass
class PackageResult:
    action: str = ""
    elapsed: float = 0.0
    output: collections.deque[str] = field(
        default_factory=lambda: collections.deque(maxlen=FAILED_OUTPUT_LIMIT)
    )


def parse_events(lines: list[str]) -> dict[str, PackageResult]:
    results: dict[str, PackageResult] = {}

    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        package = event.get("Package")
        if not isinstance(package, str) or package == "":
            continue

        result = results.setdefault(package, PackageResult())
        action = event.get("Action")
        if action == "output":
            output = event.get("Output")
            if isinstance(output, str):
                result.output.append(output.rstrip("\n"))
            continue

        if action in {"pass", "fail", "skip"} and "Test" not in event:
            result.action = action
            elapsed = event.get("Elapsed", 0.0)
            if isinstance(elapsed, (int, float)):
                result.elapsed = float(elapsed)

    return results


def format_duration(seconds: float) -> str:
    if seconds >= 60:
        minutes, remainder = divmod(seconds, 60)
        return f"{int(minutes)}m{remainder:04.1f}s"
    return f"{seconds:.1f}s"


def print_summary(
    results: dict[str, PackageResult], *, label: str, top: int, out: object = sys.stdout
) -> None:
    packages = [
        (package, result)
        for package, result in results.items()
        if result.action in {"pass", "fail", "skip"}
    ]
    packages.sort(key=lambda item: item[1].elapsed, reverse=True)

    total = sum(result.elapsed for _, result in packages)
    print(f"Go test package timing ({label})", file=out)
    print(f"packages: {len(packages)}; summed package time: {format_duration(total)}", file=out)
    print(f"slowest {min(top, len(packages))} packages:", file=out)
    for package, result in packages[:top]:
        print(
            f"  {format_duration(result.elapsed):>8}  {result.action:<4}  {package}",
            file=out,
        )

    failures = [(package, result) for package, result in packages if result.action == "fail"]
    if not failures:
        return

    print("failed package output tails:", file=out)
    for package, result in failures:
        print(f"--- {package} ---", file=out)
        for line in result.output:
            print(line, file=out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize package timings from go test -json output."
    )
    parser.add_argument("--label", default="go test", help="label printed in the summary")
    parser.add_argument("--top", type=int, default=20, help="number of slow packages to print")
    args = parser.parse_args()

    if args.top < 1:
        parser.error("--top must be at least 1")

    print_summary(parse_events(sys.stdin.readlines()), label=args.label, top=args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
