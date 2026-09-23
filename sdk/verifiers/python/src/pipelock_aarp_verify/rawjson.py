# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Source-faithful encoding of the unsigned receipt ``ext`` bag.

The Go reference verifier hashes a v1 receipt as ``json.Marshal(Receipt)``.
The top-level ``ext`` bag is a ``json.RawMessage``, so its bytes in that
preimage are the SOURCE bytes of the ext value, compacted and HTML-escaped by
``encoding/json``, with key order, number spelling, and string escape spelling
kept verbatim. Re-serializing a parsed value cannot reproduce that: number text
and escape spelling are lost at parse time. This module recovers the ext
value's source span from the recorder line and re-encodes it the way Go does,
so the chain link hash matches the Go producer byte for byte. The ext VALUE
stays unsigned and advisory; only its bytes join the link hash.
"""

from __future__ import annotations

import json
from typing import Any

_WHITESPACE = frozenset(" \t\n\r")
_GO_ESCAPES = {
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    chr(0x2028): "\\u2028",
    chr(0x2029): "\\u2029",
}


class SourcedReceipt(dict):  # type: ignore[type-arg]
    """A parsed receipt that remembers the Go-encoded bytes of its ext bag."""

    __slots__ = ("ext_go_bytes", "ext_snapshot")

    def __init__(self, value: dict[str, Any], ext_go_bytes: str) -> None:
        super().__init__(value)
        self.ext_go_bytes = ext_go_bytes
        self.ext_snapshot = _snapshot(value.get("ext"))


def _snapshot(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i] in _WHITESPACE:
        i += 1
    return i


def _skip_string(text: str, i: int) -> int:
    i += 1
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        i += 1
        if ch == '"':
            return i
    raise ValueError("unterminated JSON string")


def _skip_value(text: str, i: int) -> int:
    first = text[i]
    if first == '"':
        return _skip_string(text, i)
    if first in "{[":
        depth = 0
        while i < len(text):
            ch = text[i]
            if ch == '"':
                i = _skip_string(text, i)
                continue
            if ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        raise ValueError("unterminated JSON container")
    while i < len(text) and text[i] not in _WHITESPACE and text[i] not in ",}]":
        i += 1
    return i


def object_member_span(
    text: str, object_start: int, key: str
) -> tuple[int, int] | None:
    """Return the source span of ``key``'s value in the object at ``object_start``.

    The text must already have passed a strict parse and the duplicate-key
    check, so each key appears at most once.
    """
    i = _skip_ws(text, object_start)
    if i >= len(text) or text[i] != "{":
        return None
    i = _skip_ws(text, i + 1)
    if i < len(text) and text[i] == "}":
        return None
    while i < len(text):
        if text[i] != '"':
            raise ValueError("expected JSON object key")
        key_end = _skip_string(text, i)
        name = json.loads(text[i:key_end])
        i = _skip_ws(text, key_end)
        if i >= len(text) or text[i] != ":":
            raise ValueError("expected ':' after JSON object key")
        start = _skip_ws(text, i + 1)
        end = _skip_value(text, start)
        if name == key:
            return start, end
        i = _skip_ws(text, end)
        if i < len(text) and text[i] == ",":
            i = _skip_ws(text, i + 1)
            continue
        return None
    return None


def go_raw_message_bytes(raw: str) -> str:
    """Reproduce ``encoding/json``'s output for a ``json.RawMessage``.

    Insignificant whitespace is removed and <, >, &, U+2028 and U+2029 are
    written as six-byte lowercase-hex unicode escapes. Every other character,
    including existing escape sequences and number text, is copied verbatim.
    """
    out: list[str] = []
    in_string = False
    i = 0
    while i < len(raw):
        ch = raw[i]
        if in_string:
            if ch == "\\":
                out.append(raw[i : i + 2])
                i += 2
                continue
            if ch == '"':
                in_string = False
        else:
            if ch in _WHITESPACE:
                i += 1
                continue
            if ch == '"':
                in_string = True
        out.append(_GO_ESCAPES.get(ch, ch))
        i += 1
    return "".join(out)


def recorder_line_ext_bytes(line: str) -> str | None:
    """Return the Go-encoded ext bytes of the receipt in a recorder line."""
    detail = object_member_span(line, 0, "detail")
    if detail is None:
        return None
    ext = object_member_span(line, detail[0], "ext")
    if ext is None:
        return None
    return go_raw_message_bytes(line[ext[0] : ext[1]])


def ext_source_bytes(receipt: dict[str, Any]) -> str | None:
    """Return recorded ext bytes while they still describe ``receipt["ext"]``."""
    if not isinstance(receipt, SourcedReceipt):
        return None
    if _snapshot(receipt.get("ext")) != receipt.ext_snapshot:
        return None
    return receipt.ext_go_bytes
