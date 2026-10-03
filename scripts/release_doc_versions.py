#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Reject stale current-release references in Pipelock operator documentation.

This deliberately recognizes a small list of shipped installation surfaces.
It does not attempt to interpret arbitrary version numbers in prose.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


RELEASE_TAG_RE = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$"
)
VERSION_RE = re.compile(
    r"v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
)

SURFACE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "git clone release branch",
        re.compile(
            r"git\s+clone(?=[^\n]*https://github\.com/luckyPipewrench/pipelock(?:\.git)?)"
            r"[^\n]*?(?:--branch(?:=|\s+)|-b\s+)(?P<version>[^\s]+)"
        ),
    ),
    (
        "Docker image tag",
        re.compile(
            r"ghcr\.io/luckypipewrench/pipelock:(?P<version>[0-9A-Za-z._+-]+)"
        ),
    ),
    (
        "Helm chart version",
        re.compile(
            r"helm\s+(?:install|upgrade|pull)\b[^\n]*?"
            r"oci://ghcr\.io/luckypipewrench/charts/pipelock[^\n]*?"
            r"--version\s+(?P<version>[0-9A-Za-z._+-]+)"
        ),
    ),
    (
        "release download command",
        re.compile(r"gh\s+release\s+download\s+(?P<version>v?[0-9][^\s`\"']*)"),
    ),
    (
        "GitHub Action tag",
        re.compile(r"uses:\s*luckyPipewrench/pipelock(?:/[^@\s]+)?@(?P<version>v[0-9][^\s`\"']*)"),
    ),
    (
        "release archive URL",
        re.compile(
            r"https://github\.com/luckyPipewrench/pipelock/releases/download/"
            r"(?P<tag>[^/\s`\"']+)/pipelock_(?P<version>[^/_\s`\"']+)"
            r"_(?:linux|darwin|windows)_"
        ),
    ),
    (
        "GitHub Action version comment",
        re.compile(
            r"uses:\s*luckyPipewrench/pipelock(?:/[^@\s]+)?@"
            r"[0-9a-fA-F]{40}\s+#\s*(?P<version>v?[^\s]+)"
        ),
    ),
)

HEALTH_VERSION = re.compile(
    r'"version"\s*:\s*"(?P<version>[^"\s]+)"'
)

REQUIRED_SURFACES = (
    "git clone release branch",
    "Docker image tag",
    "Helm chart version",
    "release archive URL",
    "GitHub Action version comment",
    "health response version",
)


def _docs_files(root: Path) -> list[Path]:
    candidates = [root / "README.md"]
    for directory in (root / "docs", root / "examples", root / ".github" / "workflows"):
        if directory.is_dir():
            candidates.extend(path for path in directory.rglob("*") if path.is_file())
    candidates.append(root / "action.yml")

    files: list[Path] = []
    for path in candidates:
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        lowered = relative.lower()
        if path.name.lower().startswith("changelog") or path.name.lower() == "changes.md":
            continue
        if "/benchmark" in lowered or lowered.startswith("benchmarks/"):
            continue
        if path.suffix.lower() not in {".md", ".yml", ".yaml", ".sh", ".json", ".toml"}:
            continue
        files.append(path)
    return sorted(set(files))


def check(root: Path, release_tag: str) -> list[str]:
    if not RELEASE_TAG_RE.fullmatch(release_tag):
        return [
            f"release-doc-version: malformed release tag {release_tag!r}; "
            "expected vMAJOR.MINOR.PATCH[-prerelease]"
        ]

    expected_bare = release_tag[1:]
    observed: dict[str, int] = {surface: 0 for surface in REQUIRED_SURFACES}
    issues: list[str] = []

    for path in _docs_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            return [f"release-doc-version: cannot read {relative}: {error}"]

        logical_lines: list[tuple[int, str]] = []
        pending = ""
        first_line = 1
        for number, line in enumerate(lines, start=1):
            if not pending:
                first_line = number
            pending += line.rstrip().removesuffix("\\") + " "
            if line.rstrip().endswith("\\"):
                continue
            logical_lines.append((first_line, pending))
            pending = ""
        if pending:
            logical_lines.append((first_line, pending))

        for number, line in logical_lines:
            references: list[tuple[str, str, bool | None]] = []
            for surface, pattern in SURFACE_PATTERNS:
                for match in pattern.finditer(line):
                    if surface == "release archive URL":
                        references.append((surface, match.group("tag"), True))
                    references.append((surface, match.group("version").removesuffix("."), surface in {"git clone release branch", "GitHub Action version comment", "GitHub Action tag", "release download command"}))

            if relative == "docs/guides/health.md":
                for match in HEALTH_VERSION.finditer(line):
                    references.append(("health response version", match.group("version"), None))

            for surface, reference, prefixed in references:
                # Generic placeholders and intentional floating tags such as
                # `latest` are not current-version pins. A numeric-looking
                # malformed value remains recognized and fails closed.
                if not re.match(r"^[vV0-9]", reference):
                    continue
                observed[surface] = observed.get(surface, 0) + 1
                # A recognized numeric reference with malformed SemVer must
                # fail instead of disappearing from the version comparison.
                if not VERSION_RE.fullmatch(reference):
                    issues.append(
                        f"{relative}:{number}: {surface} has malformed version {reference!r}; "
                        f"expected {release_tag}"
                    )
                    continue
                if prefixed is not None and reference.startswith("v") != prefixed:
                    issues.append(f"{relative}:{number}: {surface} has incorrect v prefix {reference!r}; expected {release_tag if prefixed else expected_bare}")
                    continue
                normalized = reference[1:] if reference.startswith("v") else reference
                if normalized != expected_bare:
                    issues.append(
                        f"{relative}:{number}: {surface} pins {reference!r}, "
                        f"expected {release_tag if reference.startswith('v') else expected_bare}"
                    )

    for surface, count in observed.items():
        if count == 0:
            issues.append(f"missing required current-release surface: {surface}")

    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("release_tag")
    args = parser.parse_args(argv)

    issues = check(args.repository.resolve(), args.release_tag)
    if issues:
        print("release-doc-version: FAILED", file=sys.stderr)
        for issue in issues:
            print(f"  [FAIL] {issue}", file=sys.stderr)
        return 1
    print(f"release-doc-version: OK ({args.release_tag})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
