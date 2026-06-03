# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""RFC 8785 JCS canonicalization, ported byte-for-byte from the Go reference.

The reference is ``internal/contract/canonicalize.go``. Two verifiers in two
languages that canonicalize the same value MUST produce byte-identical output;
any divergence is the bug class the AARP corpus exists to kill. The subtle parts
this module reproduces exactly:

  - Strings are NFC-normalized (``unicodedata.normalize("NFC", s)``).
  - Object keys are sorted ascending by Unicode code point (Python's default
    ``str`` ordering is by code point, which is correct).
  - Compact output: no whitespace, ``,`` and ``:`` separators only.
  - Per-string escaping matches Go ``json.Marshal``: ``<`` ``>`` ``&`` are
    escaped to ``\\u003c`` ``\\u003e`` ``\\u0026``; U+2028 and U+2029 become
    ``\\u2028`` ``\\u2029``; control characters use the Go short forms where Go
    uses them (``\\b \\t \\n \\f \\r``) and ``\\u00xx`` otherwise; all other
    code points (including DEL U+007F and any non-ASCII) are emitted raw UTF-8.
  - Floats are rejected; integers are emitted verbatim from their source text.
  - NFC key collisions are rejected as duplicate keys.
"""

from __future__ import annotations

import unicodedata
from typing import Any

from .number import IJSONNumber


class CanonicalizeError(Exception):
    """A value could not be canonicalized (float, bad type, or key collision)."""


# Short escape forms Go's encoder emits for these control characters. Every
# other control character below U+0020 is emitted as ``\u00xx``.
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}


def _replace_surrogates(s: str) -> str:
    """Match Go encoding/json: unpaired UTF-16 surrogates decode as U+FFFD."""
    return "".join("\ufffd" if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in s)


def _escape_string(s: str) -> str:
    """Return the JSON string literal for ``s`` exactly as Go ``json.Marshal``.

    ``s`` is NFC-normalized first, matching the Go canonicalizer which calls
    ``norm.NFC.String`` on every string and map key.
    """
    s = unicodedata.normalize("NFC", _replace_surrogates(s))
    out = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[code])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        elif ch == "<":
            out.append("\\u003c")
        elif ch == ">":
            out.append("\\u003e")
        elif ch == "&":
            out.append("\\u0026")
        elif code == 0x2028:
            out.append("\\u2028")
        elif code == 0x2029:
            out.append("\\u2029")
        else:
            # All other code points (DEL U+007F included) emit raw UTF-8.
            out.append(ch)
    out.append('"')
    return "".join(out)


def _canon_into(parts: list[str], v: Any) -> None:
    if v is None:
        parts.append("null")
        return
    if v is True:
        parts.append("true")
        return
    if v is False:
        parts.append("false")
        return
    if isinstance(v, str):
        parts.append(_escape_string(v))
        return
    if isinstance(v, IJSONNumber):
        # Source-text integer literal, already validated as a safe integer by the
        # number-safety pass. Emit verbatim so the canonical bytes are stable.
        parts.append(v.literal)
        return
    if isinstance(v, bool):  # pragma: no cover - handled above, kept for clarity
        parts.append("true" if v else "false")
        return
    if isinstance(v, int):
        parts.append(str(v))
        return
    if isinstance(v, float):
        raise CanonicalizeError(
            "float not allowed in canonicalization; use decimal string"
        )
    if isinstance(v, (list, tuple)):
        parts.append("[")
        for i, item in enumerate(v):
            if i > 0:
                parts.append(",")
            _canon_into(parts, item)
        parts.append("]")
        return
    if isinstance(v, dict):
        # Track NFC-normalized key (for sort + output) alongside the original
        # (for value lookup), mirroring the Go canonicalizer.
        pairs = []
        for k in v:
            if not isinstance(k, str):
                raise CanonicalizeError(f"non-string map key: {k!r}")
            pairs.append((unicodedata.normalize("NFC", k), k))
        pairs.sort(key=lambda p: p[0])
        for i in range(1, len(pairs)):
            if pairs[i][0] == pairs[i - 1][0] and pairs[i][1] != pairs[i - 1][1]:
                raise CanonicalizeError(
                    f"duplicate key in JSON object: NFC collision between "
                    f"{pairs[i - 1][1]!r} and {pairs[i][1]!r}"
                )
        parts.append("{")
        for i, (nfc_key, orig_key) in enumerate(pairs):
            if i > 0:
                parts.append(",")
            parts.append(_escape_string(nfc_key))
            parts.append(":")
            _canon_into(parts, v[orig_key])
        parts.append("}")
        return
    raise CanonicalizeError(f"canonicalize: unsupported type {type(v).__name__}")


def canonicalize(v: Any) -> bytes:
    """Return the RFC 8785 JCS canonical bytes for ``v`` (UTF-8 encoded)."""
    parts: list[str] = []
    _canon_into(parts, v)
    return "".join(parts).encode("utf-8")
