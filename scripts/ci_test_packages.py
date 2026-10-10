#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Print the package list, or the test selector, for a CI test shard.

Package shards
--------------
Three heavy package trees run on their own shards and every other package is
spread round-robin over the rest shards. The union of all package shards is
exactly `go list ./...`.

Test sub-shards
---------------
The proxy and scanner trees are each too slow for one runner, so their tests
are divided by top-level test name across sub-shards (`proxy-0`, `proxy-1`,
...). Every sub-shard of a tree runs the same packages with a different
selector:

* sub-shard i < n-1 runs `-run` of the names packed into bucket i, longest
  measured test first onto the least-loaded bucket using
  scripts/ci_test_durations.json (a stable name hash when a tree has no
  measurements);
* the last sub-shard runs `-skip` of the union of every earlier bucket.

That makes the split complete and disjoint by construction rather than by the
accuracy of the name inventory. A test the inventory never saw (a new file, an
unusual declaration) matches no `-run` bucket and is not skipped by the last
sub-shard, so it still runs exactly once. The inventory only affects balance,
which is why it is a cheap source scan rather than a compile of every test
binary. `--check-partition` compares the selectors against `go test -list`
under the real build tags for release verification.

A name the inventory lists that does not exist under the current build tags is
harmless: no test matches it. Benchmarks are not listed because these shards
never pass -bench.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

HEAVY_TREES = {
    "proxy": "internal/proxy",
    "scanner": "internal/scanner",
    "mcp": "internal/mcp",
    "runtime": "internal/cli/runtime",
}
# Number of test-name sub-shards per heavy tree. A tree absent here runs as a
# single shard named after the tree.
TEST_SPLITS = {
    "proxy": 5,
    "scanner": 3,
    "mcp": 5,
    "runtime": 2,
}
REST_SHARDS = ("rest-0", "rest-1", "rest-2", "rest-3")

# Trees whose coverage is collected by a separate non-race pass instead of the
# race run. -race forces atomic coverage counters, which made the scanner's
# tight matching loops two to three times slower; the same tests without -race
# and with set-mode coverage take a fraction of the race run.
SEPARATE_COVERAGE_TREES = frozenset({"scanner"})

# Predicted-load budget per shard, in seconds. A shard's test step should finish
# in about ten minutes so the whole run, security scan and aggregates included,
# stays under fifteen.
SHARD_BUDGET_SECONDS = 600
# Rest shards run their packages two at a time (-p=2), so summed package time
# overstates wall time by about that factor.
REST_PACKAGE_PARALLELISM = 2
# The non-race coverage pass of a separate-coverage tree, as a fraction of its
# race pass: scanner-1 took 72-83s without -race against about 370s with it.
COVERAGE_PASS_FRACTION = 0.25
# Least cost charged to a test with no measurement.
MIN_UNMEASURED_SECONDS = 1.0

# Measured race-test seconds per top-level test, used to balance sub-shards by
# time instead of by name count. Regenerate it from CI shard timings with
# scripts/ci_test_durations.py when shards drift past the CI time budget.
DURATIONS_FILE = ROOT / "scripts" / "ci_test_durations.json"


def _heavy_shard_names() -> tuple[str, ...]:
    names: list[str] = []
    for tree in HEAVY_TREES:
        count = TEST_SPLITS.get(tree, 1)
        if count == 1:
            names.append(tree)
        else:
            names.extend(f"{tree}-{index}" for index in range(count))
    return tuple(names)


HEAVY_SHARDS = _heavy_shard_names()
SHARDS = (*HEAVY_SHARDS, *REST_SHARDS)

# The kernel refuses a single argv entry longer than 128 KiB (MAX_ARG_STRLEN),
# and `go test` forwards the selector to the test binary as one argument. Keep
# clear of that with room for the flag prefix; a tree that outgrows it needs a
# larger split count, and failing here says so instead of failing exec later.
MAX_SELECTOR_BYTES = 120_000

# Top-level functions `go test` runs under -run/-skip. Matching is deliberately
# loose (a helper such as `func TestHelper(x int)` is also listed): an extra
# name only shifts balance, while a missed name still runs in the last
# sub-shard. Receivers (`func (r T) TestX`) are methods, never tests.
TEST_FUNC_RE = re.compile(r"^func[ \t]+((?:Test|Fuzz|Example)\w*)[ \t]*[\[(]", re.MULTILINE)
TEST_KIND_PREFIXES = ("Test", "Fuzz", "Example")


def list_packages(tags: str) -> list[str]:
    cmd = ["go", "list"]
    if tags:
        cmd.extend(["-tags", tags])
    cmd.append("./...")
    result = subprocess.run(cmd, check=True, text=True, capture_output=True, cwd=ROOT)
    return [line for line in result.stdout.splitlines() if line]


def package_suffix(package: str) -> str:
    marker = "/internal/"
    if marker not in package:
        return ""
    # Classify from the first internal/ directory. Using the last occurrence
    # would incorrectly move internal/foo/internal/proxy into the proxy shard.
    return "internal/" + package.split(marker, 1)[1]


def package_in_tree(package: str, root: str) -> bool:
    suffix = package_suffix(package)
    return suffix == root or suffix.startswith(root + "/")


def shard_tree(shard: str) -> tuple[str, int, int] | None:
    """Return (tree, sub-shard index, sub-shard count) for a heavy shard."""
    if shard in HEAVY_TREES and TEST_SPLITS.get(shard, 1) == 1:
        return shard, 0, 1
    tree, sep, index = shard.rpartition("-")
    if sep and tree in TEST_SPLITS and index.isdigit():
        count = TEST_SPLITS[tree]
        position = int(index)
        if 0 <= position < count and shard == f"{tree}-{position}":
            return tree, position, count
    return None


# One shard per distinct package list: the first sub-shard of each split tree
# stands for all of its sub-shards, which select the same packages.
PACKAGE_SHARDS = tuple(
    shard for shard in SHARDS if shard in REST_SHARDS or shard_tree(shard)[1] == 0
)


def select_packages(
    packages: list[str], shard: str, package_weights: dict[str, float] | None = None
) -> list[str]:
    """Return the packages a shard runs.

    Rest packages are dealt round-robin by name, or, with measured package
    seconds, packed longest first onto the least-loaded rest shard. Either way
    every rest package lands in exactly one rest shard.
    """
    heavy_roots = tuple(HEAVY_TREES.values())
    if shard in REST_SHARDS:
        rest_packages = sorted(
            pkg for pkg in packages if not any(package_in_tree(pkg, root) for root in heavy_roots)
        )
        shard_index = REST_SHARDS.index(shard)
        if package_weights:
            buckets = partition_names(rest_packages, len(REST_SHARDS), package_weights)
            return buckets[shard_index]
        return [pkg for index, pkg in enumerate(rest_packages) if index % len(REST_SHARDS) == shard_index]

    located = shard_tree(shard)
    if located is None:
        raise ValueError(f"unknown shard {shard!r}")
    wanted = HEAVY_TREES[located[0]]
    selected = [pkg for pkg in packages if package_in_tree(pkg, wanted)]
    if not selected:
        raise ValueError(f"no packages matched shard {shard!r}")
    return selected


def tree_test_names(root: Path) -> list[str]:
    """Inventory top-level test, fuzz and example names under a package tree."""
    names: set[str] = set()
    for directory, subdirs, files in os.walk(root):
        # testdata holds fixtures the go tool never compiles as package tests.
        subdirs[:] = sorted(d for d in subdirs if d != "testdata")
        for filename in files:
            if filename.endswith("_test.go"):
                text = (Path(directory) / filename).read_text(encoding="utf-8", errors="replace")
                names.update(TEST_FUNC_RE.findall(text))
    return sorted(names)


def name_bucket(name: str, count: int) -> int:
    """Stable bucket for a test name: independent of order, run, and hash seed."""
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % count


def exact_names_regex(names: list[str]) -> str:
    """Return a Go regexp that matches exactly the given top-level names.

    Both anchors sit outside one group, so `TestScan` cannot match
    `TestScanTextForDLP` and nothing can match a longer or shorter name. Names
    are grouped under their kind prefix only to keep the argument short.
    The pattern contains no `/`, so go test applies it to top-level names and
    leaves every subtest of a selected test to run.
    """
    if not names:
        raise ValueError("refusing to build a selector for an empty name set")
    groups: dict[str, list[str]] = {}
    other: list[str] = []
    for name in sorted(set(names)):
        prefix = next((p for p in TEST_KIND_PREFIXES if name.startswith(p)), None)
        if prefix is None:
            other.append(re.escape(name))
        else:
            groups.setdefault(prefix, []).append(re.escape(name[len(prefix):]))
    alternatives = [f"{prefix}(?:{'|'.join(rests)})" for prefix, rests in groups.items()]
    alternatives.extend(other)
    return "^(?:" + "|".join(alternatives) + ")$"


def load_durations(path: Path = DURATIONS_FILE) -> dict[str, dict[str, float]]:
    """Read measured top-level test seconds per tree; a missing file means none."""
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    trees = data.get("trees") if isinstance(data, dict) else None
    if not isinstance(trees, dict):
        raise ValueError(f"{path.name}: expected a 'trees' object")
    return {tree: _seconds_map(path, tree, tests) for tree, tests in trees.items()}


def load_package_durations(path: Path = DURATIONS_FILE) -> dict[str, float]:
    """Read measured seconds per rest-shard package; absent means round-robin."""
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "packages" not in data:
        return {}
    return _seconds_map(path, "packages", data["packages"])


def _seconds_map(path: Path, label: str, values: object) -> dict[str, float]:
    if not isinstance(values, dict):
        raise ValueError(f"{path.name}: {label!r} must map names to seconds")
    clean: dict[str, float] = {}
    for name, seconds in values.items():
        if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or not math.isfinite(seconds) or seconds < 0:
            raise ValueError(f"{path.name}: {label}.{name} must be non-negative seconds")
        clean[name] = float(seconds)
    return clean


def partition_names(
    names: list[str], count: int, weights: dict[str, float] | None = None
) -> list[list[str]]:
    """Split names into count buckets.

    Without weights a name's bucket is a stable hash, which balances counts but
    not time. With measured weights, names are packed longest first onto the
    least-loaded bucket so a few slow tests cannot pile onto one shard. A name
    with no measurement is charged the median measured time. Ties break on the
    bucket index and names are visited in a fixed order, so the result depends
    only on the inputs.
    """
    unique = sorted(set(names))
    buckets: list[list[str]] = [[] for _ in range(count)]
    if not weights:
        for name in unique:
            buckets[name_bucket(name, count)].append(name)
        return buckets
    known = sorted(weights[name] for name in unique if name in weights)
    default = known[len(known) // 2] if known else 1.0
    loads = [0.0] * count
    for name in sorted(unique, key=lambda n: (-weights.get(n, default), n)):
        # Equal loads (including all-zero measurements) fall back to the
        # bucket with the fewest names, so no bucket is left empty.
        target = min(range(count), key=lambda i: (loads[i], len(buckets[i]), i))
        buckets[target].append(name)
        loads[target] += weights.get(name, default)
    for bucket in buckets:
        bucket.sort()
    return buckets


def shard_selector(
    shard: str, names: list[str] | None = None, weights: dict[str, float] | None = None
) -> str:
    """Return the go test selector flag for a shard, or "" when it runs all tests.

    With names omitted, the real inventory and the checked-in durations are
    used. Passing names without weights keeps the unweighted hash split.
    """
    located = shard_tree(shard)
    if located is None or located[2] == 1:
        if located is None and shard not in REST_SHARDS:
            raise ValueError(f"unknown shard {shard!r}")
        return ""
    tree, index, count = located
    if names is None:
        names = tree_test_names(ROOT / HEAVY_TREES[tree])
        if weights is None:
            weights = load_durations().get(tree)
    buckets = partition_names(names, count, weights)
    for position, bucket in enumerate(buckets):
        if not bucket:
            raise ValueError(f"sub-shard {tree}-{position} would select no tests")
    if index < count - 1:
        selector = "-run=" + exact_names_regex(buckets[index])
    else:
        earlier = [name for bucket in buckets[:-1] for name in bucket]
        selector = "-skip=" + exact_names_regex(earlier)
    if len(selector.encode("utf-8")) > MAX_SELECTOR_BYTES:
        if index < count - 1:
            remedy = f"raise TEST_SPLITS[{tree!r}]"
        else:
            # The final sub-shard skips every earlier bucket, so more splits
            # make its selector longer, not shorter.
            remedy = (
                f"the final sub-shard skips every earlier bucket; lower TEST_SPLITS[{tree!r}] "
                "or split the tree's packages into separate heavy trees"
            )
        raise ValueError(
            f"selector for {shard} is {len(selector)} bytes, over {MAX_SELECTOR_BYTES}; {remedy}"
        )
    return selector


def selector_selects(selector: str, name: str) -> bool:
    """Evaluate a selector against a top-level name the way go test does."""
    if not selector:
        return True
    flag, _, pattern = selector.partition("=")
    matched = re.search(pattern, name) is not None
    if flag == "-run":
        return matched
    if flag == "-skip":
        return not matched
    raise ValueError(f"unknown selector flag {flag!r}")


def go_test_list(packages: list[str], tags: str) -> list[str]:
    """Top-level names `go test -list` reports, one entry per (package, name)."""
    cmd = ["go", "test"]
    if tags:
        cmd.extend(["-tags", tags])
    cmd.extend(["-list", ".*", *packages])
    result = subprocess.run(cmd, check=True, text=True, capture_output=True, cwd=ROOT)
    names = []
    for line in result.stdout.splitlines():
        # Package status lines ("ok", "?") are not names. Benchmarks never run
        # in these shards (no -bench), so they are not part of the partition.
        if line.startswith(TEST_KIND_PREFIXES):
            names.append(line)
    return names


def partition_errors(listed: list[str], selectors: dict[str, str]) -> list[str]:
    """Return every listed name not selected by exactly one sub-shard."""
    errors = []
    for name in listed:
        picked = [shard for shard, selector in selectors.items() if selector_selects(selector, name)]
        if len(picked) != 1:
            errors.append(f"{name}: selected by {picked or 'no sub-shard'}")
    return errors


def check_partition(tags: str, only_tree: str | None = None) -> int:
    packages = list_packages(tags)
    status = 0
    for tree, count in TEST_SPLITS.items():
        if only_tree is not None and tree != only_tree:
            continue
        shards = [f"{tree}-{index}" for index in range(count)]
        tree_packages = select_packages(packages, shards[0])
        listed = go_test_list(tree_packages, tags)
        selectors = {shard: shard_selector(shard) for shard in shards}
        counts = {
            shard: sum(1 for name in listed if selector_selects(selectors[shard], name))
            for shard in shards
        }
        errors = partition_errors(listed, selectors)
        summary = " + ".join(f"{shard}={counts[shard]}" for shard in shards)
        print(f"{tree} (tags={tags or 'none'}): listed={len(listed)} {summary}")
        if errors or sum(counts.values()) != len(listed):
            status = 1
            for error in errors:
                print(f"  PARTITION ERROR {error}", file=sys.stderr)
    return status


def coverage_mode(shard: str) -> str:
    """Return "separate" when a shard's coverage comes from a non-race pass."""
    located = shard_tree(shard)
    if located is None:
        if shard in REST_SHARDS:
            return "race"
        raise ValueError(f"unknown shard {shard!r}")
    return "separate" if located[0] in SEPARATE_COVERAGE_TREES else "race"


def predicted_loads(tags: str) -> dict[str, float]:
    """Predict each shard's test seconds from the checked-in measurements.

    A sub-shard's load is the summed time of its top-level tests; a name with
    no measurement is charged its tree's median. A rest shard's load is its
    summed package time divided by the packages it runs at once, bounded
    below by the longest indivisible package.
    """
    durations = load_durations()
    loads: dict[str, float] = {}
    for tree, count in TEST_SPLITS.items():
        names = tree_test_names(ROOT / HEAVY_TREES[tree])
        weights = durations.get(tree, {})
        known = sorted(weights[name] for name in set(names) if name in weights)
        # Most tests round to 0.0s, so the median can be zero; an unmeasured
        # test must still cost something or a new slow test predicts free.
        default = max(known[len(known) // 2] if known else 1.0, MIN_UNMEASURED_SECONDS)
        # A separate-coverage tree reruns its tests without -race after the
        # race pass, in the same job.
        extra = 1.0 + (COVERAGE_PASS_FRACTION if tree in SEPARATE_COVERAGE_TREES else 0.0)
        for index, bucket in enumerate(partition_names(names, count, weights or None)):
            loads[f"{tree}-{index}"] = extra * sum(weights.get(name, default) for name in bucket)
    package_weights = load_package_durations()
    packages = list_packages(tags)
    known = sorted(package_weights.values())
    default = max(known[len(known) // 2] if known else 1.0, MIN_UNMEASURED_SECONDS)
    for shard in REST_SHARDS:
        selected = select_packages(packages, shard, package_weights)
        seconds = [package_weights.get(pkg, default) for pkg in selected]
        loads[shard] = package_makespan(seconds, REST_PACKAGE_PARALLELISM)
    return loads


def package_makespan(seconds: list[float], slots: int) -> float:
    """Worst-case finish time of whole packages run on a fixed number of slots.

    go test -p starts packages in build-graph order, not longest first, so any
    estimate that assumes a good order can come in under the real shard time.
    For any order in which a free slot never sits idle while a package waits,
    the finish time is at most total/slots + (1 - 1/slots) * longest. That
    bound is what the budget is checked against. Three 350s packages on two
    slots therefore predict 700s, and a single package can never be divided.
    """
    if not seconds:
        return 0.0
    slots = max(slots, 1)
    return sum(seconds) / slots + (1 - 1 / slots) * max(seconds)


def check_budget(tags: str, budget: float) -> int:
    # NaN compares false with everything, so it would pass every shard.
    if not math.isfinite(budget) or budget <= 0:
        print(f"ci_test_packages.py: budget must be a positive finite number of seconds, got {budget}", file=sys.stderr)
        return 2
    loads = predicted_loads(tags)
    over = {shard: load for shard, load in loads.items() if load > budget}
    for shard in SHARDS:
        mark = "  OVER" if shard in over else ""
        print(f"{shard:12s} {loads[shard]:7.0f}s{mark}")
    if over:
        print(
            f"ci_test_packages.py: {len(over)} shard(s) predicted over the {budget:.0f}s budget "
            f"(tags={tags or 'none'}); raise TEST_SPLITS for the tree, split slow tests, "
            "or refresh scripts/ci_test_durations.json if the measurements are stale",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Select CI package shard")
    parser.add_argument("--shard", choices=SHARDS, help="shard to print")
    parser.add_argument("--tags", default="", help="go build tags for go list")
    parser.add_argument(
        "--selector",
        action="store_true",
        help="print the go test -run/-skip flag for the shard instead of its packages",
    )
    parser.add_argument(
        "--check-partition",
        action="store_true",
        help="verify sub-shard selectors against go test -list (scoped to --shard's tree if given)",
    )
    parser.add_argument(
        "--coverage-mode",
        action="store_true",
        help="print race or separate: where the shard's coverage profile comes from",
    )
    parser.add_argument(
        "--check-budget",
        action="store_true",
        help="fail when the checked-in measurements predict any shard over the budget",
    )
    parser.add_argument(
        "--budget-seconds",
        type=float,
        default=SHARD_BUDGET_SECONDS,
        help=f"predicted-load budget per shard (default {SHARD_BUDGET_SECONDS})",
    )
    args = parser.parse_args()

    try:
        if args.check_budget:
            return check_budget(args.tags, args.budget_seconds)
        if args.coverage_mode:
            if not args.shard:
                parser.error("--coverage-mode needs --shard")
            print(coverage_mode(args.shard))
            return 0
        if args.check_partition:
            tree = None
            if args.shard:
                located = shard_tree(args.shard)
                if located is None or located[2] == 1:
                    print(f"{args.shard} runs every test of its packages; no partition to check")
                    return 0
                tree = located[0]
            return check_partition(args.tags, tree)
        if not args.shard:
            parser.error("--shard is required")
        if args.selector:
            print(shard_selector(args.shard))
            return 0
        packages = select_packages(list_packages(args.tags), args.shard, load_package_durations())
    except (subprocess.CalledProcessError, ValueError) as err:
        print(f"ci_test_packages.py: {err}", file=sys.stderr)
        return 1

    print(" ".join(packages))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
