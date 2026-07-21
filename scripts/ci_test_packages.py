#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Print the package list for a CI test shard."""

from __future__ import annotations

import argparse
import subprocess
import sys


HEAVY_SHARDS = {
    "proxy": "internal/proxy",
    "scanner": "internal/scanner",
    "mcp": "internal/mcp",
}
REST_SHARDS = ("rest-0", "rest-1", "rest-2")
SHARDS = (*HEAVY_SHARDS.keys(), *REST_SHARDS)


def list_packages(tags: str) -> list[str]:
    cmd = ["go", "list"]
    if tags:
        cmd.extend(["-tags", tags])
    cmd.append("./...")
    result = subprocess.run(cmd, check=True, text=True, capture_output=True)
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


def select_packages(packages: list[str], shard: str) -> list[str]:
    heavy_roots = tuple(HEAVY_SHARDS.values())
    if shard in REST_SHARDS:
        rest_packages = sorted(
            pkg for pkg in packages if not any(package_in_tree(pkg, root) for root in heavy_roots)
        )
        shard_index = REST_SHARDS.index(shard)
        return [pkg for index, pkg in enumerate(rest_packages) if index % len(REST_SHARDS) == shard_index]

    wanted = HEAVY_SHARDS[shard]
    selected = [pkg for pkg in packages if package_in_tree(pkg, wanted)]
    if not selected:
        raise ValueError(f"no packages matched shard {shard!r}")
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="Select CI package shard")
    parser.add_argument(
        "--shard",
        required=True,
        choices=SHARDS,
        help="package shard to print",
    )
    parser.add_argument("--tags", default="", help="go build tags for go list")
    args = parser.parse_args()

    try:
        packages = select_packages(list_packages(args.tags), args.shard)
    except (subprocess.CalledProcessError, ValueError) as err:
        print(f"ci_test_packages.py: {err}", file=sys.stderr)
        return 1

    print(" ".join(packages))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
