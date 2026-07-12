#!/usr/bin/env python3
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
    return "internal/" + package.rsplit(marker, 1)[1]


def package_in_tree(package: str, root: str) -> bool:
    suffix = package_suffix(package)
    return suffix == root or suffix.startswith(root + "/")


def select_packages(packages: list[str], shard: str) -> list[str]:
    heavy_roots = tuple(HEAVY_SHARDS.values())
    if shard == "rest":
        return [pkg for pkg in packages if not any(package_in_tree(pkg, root) for root in heavy_roots)]

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
        choices=[*HEAVY_SHARDS.keys(), "rest"],
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
