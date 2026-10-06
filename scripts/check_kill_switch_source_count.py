#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Fail when public docs state a kill-switch source count the code does not have.

The expected count is read from Controller.Sources() in
internal/killswitch/killswitch.go, so adding or removing an activation source
moves the expectation without anyone editing this script. A doc line that
mentions the kill switch and states "<N> (independent) (activation) sources"
must use that count.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
}
COUNT_PHRASE = re.compile(
    r"\b(?P<n>\d+|" + "|".join(NUMBER_WORDS) + r")\s+(?:independent\s+)?(?:activation\s+)?sources\b",
    re.IGNORECASE,
)
SUBSET_PREFIX = re.compile(r"\b(?:its|the|these|those|other)\s+$", re.IGNORECASE)
KILL_SWITCH_LINE =re.compile(r"kill[\s-]?switch|deny-all", re.IGNORECASE)
SOURCES_FUNC = re.compile(r"func \(c \*Controller\) Sources\(\).*?\n}\n", re.DOTALL)
MAP_KEY = re.compile(r'^\s*"(?P<key>[a-z_]+)":', re.MULTILINE)
ASSIGNED_KEY = re.compile(r'sources\["(?P<key>[a-z_]+)"\]\s*=')
DOC_SUFFIXES = {".md", ".yaml", ".yml"}
SCOPE = ("README.md", "CONTRIBUTING.md", "GOVERNANCE.md", "SECURITY.md", "docs", "examples")


def expected_source_count(root: Path) -> int:
    """Count the distinct keys Sources() reports."""
    source = (root / "internal" / "killswitch" / "killswitch.go").read_text(encoding="utf-8")
    match = SOURCES_FUNC.search(source)
    if match is None:
        raise SystemExit("check_kill_switch_source_count: Sources() not found in killswitch.go")
    body = match.group(0)
    keys = {m.group("key") for m in MAP_KEY.finditer(body)}
    keys |= {m.group("key") for m in ASSIGNED_KEY.finditer(body)}
    if not keys:
        raise SystemExit("check_kill_switch_source_count: no source keys parsed from Sources()")
    return len(keys)


def doc_files(root: Path):
    for name in SCOPE:
        path = root / name
        if path.is_file():
            yield path
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix in DOC_SUFFIXES:
                    yield child


def stale_claims(root: Path, expected: int) -> list[str]:
    problems: list[str] = []
    for path in doc_files(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if not KILL_SWITCH_LINE.search(line):
                continue
            for match in COUNT_PHRASE.finditer(line):
                # "its three sources" names a subset (the Conductor-driven ones),
                # not the total.
                if SUBSET_PREFIX.search(line[: match.start()]):
                    continue
                raw = match.group("n").lower()
                stated = int(raw) if raw.isdigit() else NUMBER_WORDS[raw]
                if stated != expected:
                    problems.append(
                        f"{path.relative_to(root)}:{number}: says {match.group(0)!r}, "
                        f"killswitch.go reports {expected} sources"
                    )
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    expected = expected_source_count(args.root)
    problems = stale_claims(args.root, expected)
    if problems:
        print("\n".join(problems))
        print(f"\ndocs-check: failed: stale kill-switch source count (expected {expected})")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
