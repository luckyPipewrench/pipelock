#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Print a compact package timing summary from `go test -json` output."""

from __future__ import annotations

import argparse
import collections
import json
import math
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field


FAILED_OUTPUT_LIMIT = 80


def escape_terminal_text(value: str) -> str:
    return "".join(
        character if character.isprintable() else f"\\u{ord(character):04x}"
        for character in value
    )


def normalize_elapsed(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    try:
        elapsed = float(value)
    except OverflowError:
        return 0.0
    return elapsed if math.isfinite(elapsed) and elapsed > 0 else 0.0


@dataclass
class _ActionResult:
    action: str = ""
    elapsed: float = 0.0
    output: collections.deque[str] = field(
        default_factory=lambda: collections.deque(maxlen=FAILED_OUTPUT_LIMIT)
    )


@dataclass
class PackageResult(_ActionResult):
    tests: dict[str, "TestResult"] = field(default_factory=dict)


@dataclass
class TestResult(_ActionResult):
    pass


def parse_events(
    lines: Iterable[str], *, output_limit: int = FAILED_OUTPUT_LIMIT
) -> dict[str, PackageResult]:
    results: dict[str, PackageResult] = {}

    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue

        package = event.get("Package")
        if not isinstance(package, str) or package == "":
            continue

        result = results.setdefault(
            package, PackageResult(output=collections.deque(maxlen=output_limit))
        )
        action = event.get("Action")
        test = event.get("Test")
        test_result = None
        if isinstance(test, str) and test != "":
            test_result = result.tests.setdefault(
                test, TestResult(output=collections.deque(maxlen=output_limit))
            )

        if action == "output":
            output = event.get("Output")
            if isinstance(output, str):
                output_line = output.rstrip("\n")
                if test_result is not None:
                    test_result.output.append(output_line)
                else:
                    result.output.append(output_line)
            continue

        if action == "run" and test_result is not None:
            test_result.action = action
            continue

        if action in {"pass", "fail", "skip"}:
            elapsed = normalize_elapsed(event.get("Elapsed", 0.0))
            if test_result is not None:
                test_result.action = action
                test_result.elapsed = elapsed
                continue

            result.action = action
            result.elapsed = elapsed

    return results


def format_duration(seconds: float) -> str:
    if seconds >= 60:
        minutes, remainder = divmod(seconds, 60)
        return f"{int(minutes)}m{remainder:04.1f}s"
    return f"{seconds:.1f}s"


def print_summary(
    results: dict[str, PackageResult],
    *,
    label: str,
    top: int,
    top_tests: int = 25,
    out: object | None = None,
) -> None:
    if out is None:
        out = sys.stdout
    packages = [
        (package, result)
        for package, result in results.items()
        if result.action in {"pass", "fail", "skip"}
    ]
    packages.sort(key=lambda item: item[1].elapsed, reverse=True)

    total = sum(result.elapsed for _, result in packages)
    print(f"Go test package timing ({escape_terminal_text(label)})", file=out)
    print(f"packages: {len(packages)}; summed package time: {format_duration(total)}", file=out)
    print(f"slowest {min(top, len(packages))} packages:", file=out)
    for package, result in packages[:top]:
        print(
            f"  {format_duration(result.elapsed):>8}  {result.action:<4}  "
            f"{escape_terminal_text(package)}",
            file=out,
        )

    tests = [
        (package, test, test_result)
        for package, result in packages
        for test, test_result in result.tests.items()
        if test_result.action in {"pass", "fail", "skip"}
    ]
    tests.sort(key=lambda item: item[2].elapsed, reverse=True)
    if tests:
        print(f"slowest {min(top_tests, len(tests))} tests:", file=out)
        print(
            "  elapsed values can overlap for parallel tests; they are wall-clock "
            "attribution, not exclusive CPU time",
            file=out,
        )
        for package, test, test_result in tests[:top_tests]:
            print(
                f"  {format_duration(test_result.elapsed):>8}  "
                f"{test_result.action:<4}  {escape_terminal_text(package)} "
                f"{escape_terminal_text(test)}",
                file=out,
            )

    failures = [(package, result) for package, result in packages if result.action == "fail"]
    if not failures:
        return

    all_failed_tests = [
        (package, test, test_result)
        for package, result in failures
        for test, test_result in sorted(result.tests.items())
        if test_result.action == "fail"
    ]
    if all_failed_tests:
        print("failed tests:", file=out)
        for package, test, test_result in all_failed_tests:
            print(
                f"--- {escape_terminal_text(package)} {escape_terminal_text(test)} "
                f"({format_duration(test_result.elapsed)}) ---",
                file=out,
            )
            for line in test_result.output:
                print(escape_terminal_text(line), file=out)

    interrupted_tests = [
        (package, test, test_result)
        for package, result in failures
        for test, test_result in sorted(result.tests.items())
        if test_result.action == "run" and test_result.output
    ]
    if interrupted_tests:
        print("interrupted test output:", file=out)
        for package, test, test_result in interrupted_tests:
            print(
                f"--- {escape_terminal_text(package)} {escape_terminal_text(test)} ---",
                file=out,
            )
            for line in test_result.output:
                print(escape_terminal_text(line), file=out)

    package_output_failures = [
        (package, result) for package, result in failures if result.output
    ]
    if package_output_failures:
        print("failed package output tails:", file=out)
        for package, result in package_output_failures:
            print(f"--- {escape_terminal_text(package)} ---", file=out)
            for line in result.output:
                print(escape_terminal_text(line), file=out)


def print_full_failed_output(lines: Iterable[str], results: dict[str, PackageResult]) -> None:
    """Replay failed diagnostics from disk without retaining output in memory."""
    previous = None
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            # Go and its toolchain may write text around the JSON stream. Keep
            # that evidence too; silently dropping it hides formatter failures.
            print("unparsed diagnostic: " + escape_terminal_text(line.rstrip("\n")))
            continue
        if not isinstance(event, dict):
            continue
        package = event.get("Package")
        if not isinstance(package, str):
            continue
        result = results.get(package)
        output = event.get("Output")
        if result is None or result.action != "fail" or not isinstance(output, str):
            continue
        test = event.get("Test")
        test = test if isinstance(test, str) else ""
        if test:
            test_result = result.tests.get(test)
            if test_result is None or test_result.action not in {"fail", "run"}:
                continue
            heading = "interrupted test output:" if test_result.action == "run" else "failed tests:"
        else:
            heading = "failed package output:"
        key = (package, test)
        if key != previous:
            print(heading)
            name = package + (" " + test if test else "")
            print(f"--- {escape_terminal_text(name)} ---")
            previous = key
        print(escape_terminal_text(output.rstrip("\n")))


def summarize_full_output(lines: Iterable[str], *, label: str, top: int, top_tests: int) -> dict[str, PackageResult]:
    """Spool input once, then replay selected output after final states are known."""
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as captured:
        def capture():
            for line in lines:
                captured.write(line)
                if not line.endswith("\n"):
                    captured.write("\n")
                yield line

        results = parse_events(capture(), output_limit=0)
        print_summary(results, label=label, top=top, top_tests=top_tests)
        captured.seek(0)
        print_full_failed_output(captured, results)
        return results


def has_failed_packages(results: dict[str, PackageResult]) -> bool:
    return any(result.action == "fail" for result in results.values())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize package timings from go test -json output."
    )
    parser.add_argument("--label", default="go test", help="label printed in the summary")
    parser.add_argument("--top", type=int, default=20, help="number of slow packages to print")
    parser.add_argument(
        "--top-tests", type=int, default=25, help="number of slow tests to print"
    )
    parser.add_argument(
        "--full-failed-output",
        action="store_true",
        help="retain complete output for failed packages instead of bounded tails",
    )
    parser.add_argument(
        "--allow-failed-packages",
        action="store_true",
        help="return success after reporting failed packages",
    )
    parser.add_argument(
        "--sanitize-raw",
        action="store_true",
        help="escape captured input without parsing it",
    )
    args = parser.parse_args()

    if args.top < 1:
        parser.error("--top must be at least 1")
    if args.top_tests < 1:
        parser.error("--top-tests must be at least 1")

    if args.sanitize_raw:
        for line in sys.stdin:
            print(escape_terminal_text(line.rstrip("\n")))
        return 0

    if args.full_failed_output:
        results = summarize_full_output(sys.stdin, label=args.label, top=args.top, top_tests=args.top_tests)
    else:
        results = parse_events(sys.stdin)
        print_summary(results, label=args.label, top=args.top, top_tests=args.top_tests)
    if has_failed_packages(results) and not args.allow_failed_packages:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
