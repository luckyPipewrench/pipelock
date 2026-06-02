# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Canonicalization escaping + ordering parity with Go json.Marshal / JCS."""

from __future__ import annotations

import unicodedata

import pytest

from pipelock_aarp_verify.canonical import CanonicalizeError, canonicalize
from pipelock_aarp_verify.number import IJSONNumber


def c(v: object) -> str:
    return canonicalize(v).decode("utf-8")


def test_html_escapes_match_go():
    # Go json.Marshal escapes < > & to the < > & forms.
    assert c("<>&") == '"\\u003c\\u003e\\u0026"'


def test_line_separators_escaped():
    # U+2028 / U+2029 are escaped by Go's encoder.
    assert c("  ") == '"\\u2028\\u2029"'


def test_short_control_escapes():
    # Go uses short forms for backspace, tab, newline, formfeed, carriage return.
    assert c("\b\t\n\f\r") == '"\\b\\t\\n\\f\\r"'


def test_other_controls_use_u_form():
    # Other control chars (NUL, SOH, US, vertical tab) use \u00xx.
    assert c("\x00\x01\x1f\x0b") == '"\\u0000\\u0001\\u001f\\u000b"'


def test_quote_and_backslash_escaped_slash_is_not():
    assert c('"\\/') == '"\\"\\\\/"'


def test_non_ascii_and_del_emitted_raw():
    # Non-ASCII and DEL (U+007F) are emitted as raw UTF-8, matching Go.
    assert c("héllo\x7f") == '"héllo\x7f"'


def test_nfc_normalization_on_strings():
    # NFD 'e' + combining acute normalizes to the NFC single code point U+00E9.
    nfd = unicodedata.normalize("NFD", "é")
    assert nfd != "é"
    assert c(nfd) == '"é"'


def test_unpaired_surrogates_match_go_replacement_character():
    assert c("\ud800.example") == '"�.example"'
    assert c("\ud800A") == '"�A"'
    assert c("\udc00") == '"�"'


def test_object_keys_sorted_by_codepoint():
    assert c({"b": 1, "a": 2, "Z": 3}) == '{"Z":3,"a":2,"b":1}'


def test_nfc_key_collision_rejected():
    # NFC 'e-acute' (U+00E9) and NFD 'e' + combining acute (U+0301) are distinct
    # dict keys that normalize to the same NFC form -> duplicate key after canon.
    nfc_key = "é"
    nfd_key = unicodedata.normalize("NFD", "é")
    assert nfc_key != nfd_key
    with pytest.raises(CanonicalizeError):
        canonicalize({nfc_key: 1, nfd_key: 2})


def test_floats_rejected():
    with pytest.raises(CanonicalizeError):
        canonicalize(1.5)


def test_bool_and_null_and_int():
    assert c(True) == "true"
    assert c(False) == "false"
    assert c(None) == "null"
    assert c(42) == "42"


def test_ijson_number_emitted_verbatim():
    assert c(IJSONNumber("9007199254740991")) == "9007199254740991"


def test_nested_array_and_object():
    assert c({"x": [1, {"y": "z"}]}) == '{"x":[1,{"y":"z"}]}'


def test_unsupported_type_rejected():
    with pytest.raises(CanonicalizeError):
        canonicalize(object())


def test_non_string_key_rejected():
    with pytest.raises(CanonicalizeError):
        canonicalize({1: "a"})
