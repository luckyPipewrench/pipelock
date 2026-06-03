# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""I-JSON number safety, strict parse, and typed-string grammar tests."""

from __future__ import annotations

import pytest

from pipelock_aarp_verify.number import (
    MAX_SAFE_INTEGER,
    BadGrammarError,
    IJSONNumber,
    StrictParseError,
    UnsafeNumberError,
    enforce_safe_numbers,
    parse_json_strict,
    parse_seq,
    validate_hex256,
    validate_uint64_string,
)


def test_parse_preserves_number_literal():
    tree = parse_json_strict('{"n": 5, "big": 9007199254740991}')
    assert isinstance(tree["n"], IJSONNumber)
    assert tree["n"].literal == "5"
    assert tree["big"].literal == "9007199254740991"


def test_parse_rejects_duplicate_key():
    with pytest.raises(StrictParseError):
        parse_json_strict('{"a": 1, "a": 2}')


def test_parse_rejects_nested_duplicate_key():
    with pytest.raises(StrictParseError):
        parse_json_strict('{"o": {"a": 1, "a": 2}}')


def test_parse_rejects_trailing_tokens():
    with pytest.raises(StrictParseError):
        parse_json_strict('{"a": 1} garbage')


def test_parse_allows_trailing_whitespace():
    tree = parse_json_strict('  {"a": 1}  \n')
    assert tree["a"].literal == "1"


def test_parse_rejects_bad_syntax():
    with pytest.raises(StrictParseError):
        parse_json_strict("{not json")


def test_parse_accepts_bytes():
    tree = parse_json_strict(b'{"a": 1}')
    assert tree["a"].literal == "1"


def test_enforce_rejects_float():
    tree = parse_json_strict('{"x": 1.5}')
    with pytest.raises(UnsafeNumberError):
        enforce_safe_numbers(tree)


def test_enforce_rejects_exponent():
    tree = parse_json_strict('{"x": 1e3}')
    with pytest.raises(UnsafeNumberError):
        enforce_safe_numbers(tree)


def test_enforce_rejects_negative_zero():
    tree = parse_json_strict('{"x": -0}')
    with pytest.raises(UnsafeNumberError):
        enforce_safe_numbers(tree)


def test_enforce_rejects_out_of_range():
    tree = parse_json_strict('{"x": 9007199254740992}')
    with pytest.raises(UnsafeNumberError):
        enforce_safe_numbers(tree)


def test_enforce_rejects_out_of_range_negative():
    tree = parse_json_strict('{"x": -9007199254740992}')
    with pytest.raises(UnsafeNumberError):
        enforce_safe_numbers(tree)


def test_enforce_accepts_max_safe():
    tree = parse_json_strict(f'{{"x": {MAX_SAFE_INTEGER}}}')
    enforce_safe_numbers(tree)  # no raise


def test_enforce_walks_arrays():
    tree = parse_json_strict('{"a": [1, 2, 1.5]}')
    with pytest.raises(UnsafeNumberError):
        enforce_safe_numbers(tree)


def test_enforce_ignores_strings_bools_null():
    enforce_safe_numbers({"s": "x", "b": True, "n": None})


def test_validate_hex256_ok():
    validate_hex256("a" * 64)


def test_validate_hex256_wrong_length():
    with pytest.raises(BadGrammarError):
        validate_hex256("a" * 63)


def test_validate_hex256_uppercase_rejected():
    with pytest.raises(BadGrammarError):
        validate_hex256("A" * 64)


def test_validate_uint64_zero():
    validate_uint64_string("0")


def test_validate_uint64_leading_zero_rejected():
    with pytest.raises(BadGrammarError):
        validate_uint64_string("01")


def test_validate_uint64_empty_rejected():
    with pytest.raises(BadGrammarError):
        validate_uint64_string("")


def test_validate_uint64_non_digit_rejected():
    with pytest.raises(BadGrammarError):
        validate_uint64_string("12a")


def test_validate_uint64_overflow_rejected():
    with pytest.raises(BadGrammarError):
        validate_uint64_string(str(1 << 64))


def test_parse_seq_value():
    assert parse_seq("42") == 42


def test_parse_seq_rejects_bad():
    with pytest.raises(BadGrammarError):
        parse_seq("0x1")


def test_enforce_rejects_empty_literal():
    # An empty number literal cannot arise from json.loads, but the guard exists
    # for defense in depth; exercise it directly.
    with pytest.raises(UnsafeNumberError):
        enforce_safe_numbers(IJSONNumber(""))


def test_ijson_number_equality_and_repr():
    assert IJSONNumber("1") == IJSONNumber("1")
    assert IJSONNumber("1") != IJSONNumber("2")
    assert IJSONNumber("1") != "1"
    assert "IJSONNumber" in repr(IJSONNumber("1"))
