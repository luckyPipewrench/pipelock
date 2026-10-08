#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Rebuild scripts/ci_test_durations.json from `go test -json` output.

The sub-shard split in scripts/ci_test_packages.py balances by these measured
seconds. Feed it the JSON of race runs that cover a split tree (CI keeps each
shard's stream as a workflow artifact), and it records the elapsed time of
every top-level test in that tree, taking the slowest value seen for a name.

    python3 scripts/ci_test_durations.py --write shard-a.json shard-b.json ...

Only trees listed in TEST_SPLITS are recorded. A tree with no measurement in
the inputs keeps its previous entry, so a partial refresh never erases data.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ci_test_packages import (  # noqa: E402
    DURATIONS_FILE,
    HEAVY_TREES,
    TEST_SPLITS,
    load_durations,
    package_in_tree,
)


def tree_for_package(package: str) -> str | None:
    for tree in TEST_SPLITS:
        if package_in_tree(package, HEAVY_TREES[tree]):
            return tree
    return None


def collect(paths: list[Path]) -> dict[str, dict[str, float]]:
    measured: dict[str, dict[str, float]] = {}
    for path in paths:
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict) or event.get("Action") not in ("pass", "fail"):
                    continue
                name = event.get("Test")
                elapsed = event.get("Elapsed")
                if not isinstance(name, str) or "/" in name or not isinstance(elapsed, (int, float)):
                    continue
                tree = tree_for_package(str(event.get("Package", "")))
                if tree is None:
                    continue
                tests = measured.setdefault(tree, {})
                tests[name] = max(tests.get(name, 0.0), round(float(elapsed), 1))
    return measured


def merge(previous: dict[str, dict[str, float]], measured: dict[str, dict[str, float]]) -> dict:
    trees = {tree: dict(sorted(tests.items())) for tree, tests in previous.items() if tree in TEST_SPLITS}
    for tree, tests in measured.items():
        trees[tree] = dict(sorted(tests.items()))
    return {"trees": dict(sorted(trees.items()))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("inputs", nargs="+", type=Path, help="go test -json output files")
    parser.add_argument("--write", action="store_true", help=f"update {DURATIONS_FILE.name}")
    args = parser.parse_args()

    measured = collect(args.inputs)
    if not measured:
        print("ci_test_durations.py: no top-level results for a split tree in the inputs", file=sys.stderr)
        return 1
    result = merge(load_durations(), measured)
    for tree, tests in result["trees"].items():
        print(f"{tree}: {len(tests)} tests, {sum(tests.values()):.0f}s measured")
    text = json.dumps(result, indent=1, sort_keys=False) + "\n"
    if args.write:
        DURATIONS_FILE.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
