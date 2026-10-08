# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Split the generated group attack ZIP into shared, hook-sized test inputs.

Run with the Go-generated receipt-groups-attacks.zip as the sole argument.
The verifier suites concatenate the numbered parts before opening the ZIP.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

PART_SIZE = 450_000
PART_COUNT = 7
OUTPUT = Path(__file__).parent / "fixtures"


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: split_group_attack_fixture.py receipt-groups-attacks.zip"
        )
    source = Path(sys.argv[1]).read_bytes()
    with zipfile.ZipFile(Path(sys.argv[1])) as archive:
        if archive.testzip() is not None:
            raise SystemExit("attack fixture ZIP has a corrupt member")
    parts = [
        source[start : start + PART_SIZE] for start in range(0, len(source), PART_SIZE)
    ]
    if len(parts) != PART_COUNT:
        raise SystemExit(f"attack fixture needs {PART_COUNT} parts, got {len(parts)}")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for index, part in enumerate(parts):
        (OUTPUT / f"receipt-groups-attacks.zip.part{index:02d}").write_bytes(part)


if __name__ == "__main__":
    main()
