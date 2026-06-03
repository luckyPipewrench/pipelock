# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Strict JSON parsing and I-JSON number safety, ported from the Go reference.

Ports ``internal/contract/canonicalize.go`` (ParseJSONStrict) and
``internal/aarp/numbers.py`` (EnforceSafeNumbers + typed-string grammars).

The strict parser preserves number literals as :class:`IJSONNumber` so the
canonicalizer can emit the exact source text and the number-safety pass can
inspect the literal (float / exponent / negative-zero / range) before any lossy
float conversion. It rejects duplicate object keys at any depth and any
non-whitespace token after the top-level value.
"""

from __future__ import annotations

import json
from typing import Any

# The I-JSON safe-integer range. Outside it, a JavaScript or other-language
# verifier silently rounds to float64, changing the canonical bytes and breaking
# the signature. AARP allows raw JSON numbers ONLY inside this range.
MAX_SAFE_INTEGER = (1 << 53) - 1
MIN_SAFE_INTEGER = -((1 << 53) - 1)

HEX_DIGEST_LEN = 64


class StrictParseError(Exception):
    """The input is not strict JSON (duplicate key, trailing token, bad syntax)."""


class UnsafeNumberError(Exception):
    """A raw JSON number is a float, exponent, negative zero, or out of range."""


class BadGrammarError(Exception):
    """A typed-string field violates its declared grammar."""


class IJSONNumber:
    """A JSON number preserved as its exact source-text literal.

    Equivalent to Go's ``json.Number``: the literal is kept verbatim so float /
    exponent / negative-zero detection happens on the text, and canonical output
    emits the same bytes the producer wrote.
    """

    __slots__ = ("literal",)

    def __init__(self, literal: str) -> None:
        self.literal = literal

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"IJSONNumber({self.literal!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, IJSONNumber) and other.literal == self.literal

    def __hash__(self) -> int:  # pragma: no cover - not used as a key
        return hash(self.literal)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """object_pairs_hook that raises on a repeated key at any depth."""
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise StrictParseError(f"duplicate key in JSON object: {key!r}")
        obj[key] = value
    return obj


def parse_json_strict(data: bytes | str) -> Any:
    """Parse ``data`` rejecting duplicate keys and trailing non-whitespace tokens.

    Numbers are preserved as :class:`IJSONNumber`. Trailing whitespace is allowed
    (matching the Go reference); any other trailing token is rejected.
    """
    if isinstance(data, bytes):
        text = data.decode("utf-8")
    else:
        text = data
    decoder = json.JSONDecoder(
        object_pairs_hook=_reject_duplicates,
        parse_float=IJSONNumber,
        parse_int=IJSONNumber,
    )
    # raw_decode begins at the given index and does not itself skip leading
    # whitespace; the JSON spec permits leading whitespace, so advance past it
    # first (matching the Go decoder, which tolerates it).
    start = 0
    while start < len(text) and text[start] in " \t\n\r":
        start += 1
    try:
        value, end = decoder.raw_decode(text, start)
    except json.JSONDecodeError as exc:
        raise StrictParseError(str(exc)) from exc
    remainder = text[end:]
    if remainder.strip() != "":
        raise StrictParseError(f"trailing tokens after JSON value: {remainder[:32]!r}")
    return value


def enforce_safe_numbers(tree: Any, path: str = "$") -> None:
    """Walk a parsed tree and reject any number that is not a safe integer."""
    if isinstance(tree, IJSONNumber):
        _check_safe_number(tree.literal, path)
        return
    if isinstance(tree, dict):
        for key, value in tree.items():
            enforce_safe_numbers(value, f"{path}.{key}")
        return
    if isinstance(tree, list):
        for i, value in enumerate(tree):
            enforce_safe_numbers(value, f"{path}[{i}]")
        return
    # Strings, bools, and None carry no numeric interoperability hazard.


def _check_safe_number(lit: str, path: str) -> None:
    if lit == "":
        raise UnsafeNumberError(f"empty number at {path}")
    # Float and exponent forms are forbidden: their value-vs-text relationship is
    # exactly what diverges across language parsers.
    if any(c in lit for c in ".eE"):
        raise UnsafeNumberError(f"float or exponent form {lit!r} at {path}")
    if lit == "-0":
        raise UnsafeNumberError(f"negative zero at {path}")
    try:
        n = int(lit, 10)
    except ValueError as exc:
        raise UnsafeNumberError(f"non-integer literal {lit!r} at {path}") from exc
    if n > MAX_SAFE_INTEGER or n < MIN_SAFE_INTEGER:
        raise UnsafeNumberError(f"{lit!r} outside I-JSON safe range at {path}")


def validate_hex256(s: str) -> None:
    """Validate a lowercase-hex SHA-256 digest: exactly 64 chars from [0-9a-f]."""
    if len(s) != HEX_DIGEST_LEN:
        raise BadGrammarError(f"digest length {len(s)}, want {HEX_DIGEST_LEN}")
    for c in s:
        if not ("0" <= c <= "9" or "a" <= c <= "f"):
            raise BadGrammarError(f"digest contains non-lowercase-hex byte {c!r}")


def validate_uint64_string(s: str) -> None:
    """Validate an unsigned decimal counter: digits, no sign, no leading zero."""
    if s == "":
        raise BadGrammarError("empty unsigned counter")
    if s == "0":
        return
    if s[0] == "0":
        raise BadGrammarError(f"leading zero in counter {s!r}")
    for c in s:
        if not ("0" <= c <= "9"):
            raise BadGrammarError(f"non-digit in counter {s!r}")
    if int(s, 10) > (1 << 64) - 1:
        raise BadGrammarError(f"counter {s!r} exceeds uint64")


def parse_seq(s: str) -> int:
    """Validate a uint64 typed-string and return its numeric value."""
    validate_uint64_string(s)
    return int(s, 10)
