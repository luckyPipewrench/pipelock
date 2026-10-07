# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Generate shared Go evidence-line whitespace vectors."""

import json
from pathlib import Path

GO_SPACE = (
    0x09,
    0x0A,
    0x0B,
    0x0C,
    0x0D,
    0x20,
    0x85,
    0xA0,
    0x1680,
    0x2000,
    0x2001,
    0x2002,
    0x2003,
    0x2004,
    0x2005,
    0x2006,
    0x2007,
    0x2008,
    0x2009,
    0x200A,
    0x2028,
    0x2029,
    0x202F,
    0x205F,
    0x3000,
)
EXTRA = (0x1C, 0x1D, 0x1E, 0x1F, 0xFEFF, 0x200B)


def generate() -> list[dict[str, object]]:
    rows = []
    for point in GO_SPACE + EXTRA:
        for placement in ("whole", "leading", "trailing"):
            ch = chr(point)
            line = (
                ch
                if placement == "whole"
                else (ch + "{}" if placement == "leading" else "{}" + ch)
            )
            rows.append(
                {
                    "name": f"u{point:04x}-{placement}",
                    "codepoint": point,
                    "placement": placement,
                    "line": line,
                    "expected": ("skip" if placement == "whole" else "parse")
                    if point in GO_SPACE
                    else "reject",
                }
            )
    return rows


if __name__ == "__main__":
    target = Path(__file__).parent / "testdata" / "receipt-line-whitespace.json"
    rule = "A newline-terminated line made only of Go unicode.IsSpace code points is skipped; every other newline-terminated line is trimmed at both ends by that exact set and parsed strictly; torn final fragments retain existing handling."
    target.write_text(
        json.dumps({"rule": rule, "vectors": generate()}, ensure_ascii=True, indent=2)
        + "\n"
    )
