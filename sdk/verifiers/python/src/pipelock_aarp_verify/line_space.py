# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Go strings.TrimSpace semantics for newline-terminated evidence lines."""

GO_SPACE_CODEPOINTS = (
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
GO_SPACE = "".join(map(chr, GO_SPACE_CODEPOINTS))


def trim_go_space(line: str) -> str:
    """Trim exactly the code points accepted by Go unicode.IsSpace."""
    return line.strip(GO_SPACE)


def trim_go_space_bytes(line: bytes) -> bytes:
    return trim_go_space(line.decode("utf-8")).encode("utf-8")
