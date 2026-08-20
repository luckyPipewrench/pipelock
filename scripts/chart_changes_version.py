# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Read the Pipelock appVersion named inside Artifact Hub release notes."""

from __future__ import annotations

import re
import sys
from pathlib import Path


VERSION_RE = re.compile(
    r"^\s+description:\s*Pipelock appVersion "
    r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\."
)


def changes_appversion(chart: str) -> str:
    in_changes = False
    for line in chart.splitlines():
        if line.rstrip() == "  artifacthub.io/changes: |":
            in_changes = True
            continue
        if not in_changes:
            continue
        if line and not line.startswith("    "):
            break
        match = VERSION_RE.match(line)
        if match:
            return match.group(1)
    return ""


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: chart_changes_version.py CHART", file=sys.stderr)
        return 2
    print(changes_appversion(Path(sys.argv[1]).read_text(encoding="utf-8")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
