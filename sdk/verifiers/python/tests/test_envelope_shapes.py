# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Type-shape and structural error paths in envelope parsing."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pipelock_aarp_verify.envelope import SchemaError, unmarshal

_CORPUS = (
    Path(__file__).resolve().parents[3] / "conformance" / "testdata" / "aarp-corpus"
)


def _base() -> dict:
    return copy.deepcopy(
        json.loads(
            (_CORPUS / "golden" / "g01-single-ed25519-mediated.aarp.json").read_text()
        )
    )


def _u(obj: dict):
    return unmarshal(json.dumps(obj).encode("utf-8"))


def test_top_level_not_object():
    with pytest.raises(SchemaError):
        unmarshal(b"[]")


def test_profile_not_string():
    obj = _base()
    obj["profile"] = 1
    with pytest.raises(SchemaError):
        _u(obj)


def test_subject_not_object():
    obj = _base()
    obj["subject"] = "x"
    with pytest.raises(SchemaError):
        _u(obj)


def test_assertion_not_object():
    obj = _base()
    obj["assertion"] = "x"
    with pytest.raises(SchemaError):
        _u(obj)


def test_signatures_not_array():
    obj = _base()
    obj["signatures"] = {}
    with pytest.raises(SchemaError):
        _u(obj)


def test_signature_element_not_object():
    obj = _base()
    obj["signatures"] = ["x"]
    with pytest.raises(SchemaError):
        _u(obj)


def test_protected_not_object():
    obj = _base()
    obj["signatures"][0]["protected"] = "x"
    with pytest.raises(SchemaError):
        _u(obj)


def test_claimed_not_string_array():
    obj = _base()
    obj["assertion"]["claimed"] = [1, 2]
    with pytest.raises(SchemaError):
        _u(obj)


def test_complete_mediation_not_bool():
    obj = _base()
    obj["assertion"]["complete_mediation"] = "false"
    with pytest.raises(SchemaError):
        _u(obj)


def test_trust_domain_not_string():
    obj = _base()
    obj["assertion"]["trust_domain"] = 5
    with pytest.raises(SchemaError):
        _u(obj)


def test_evidence_refs_not_string_array():
    obj = _base()
    obj["assertion"]["evidence_refs"] = [1]
    with pytest.raises(SchemaError):
        _u(obj)


def test_crit_ext_not_string_array():
    obj = _base()
    obj["crit_ext"] = [1]
    with pytest.raises(SchemaError):
        _u(obj)


def test_protected_crit_not_string_array():
    obj = _base()
    obj["signatures"][0]["protected"]["crit"] = [1]
    with pytest.raises(SchemaError):
        _u(obj)


def test_chain_not_object():
    obj = _base()
    obj["chain"] = "x"
    with pytest.raises(SchemaError):
        _u(obj)


def test_chain_null_is_allowed():
    obj = _base()
    obj["chain"] = None
    env = _u(obj)
    assert env.chain is None


def test_missing_required_field_is_schema_error():
    obj = _base()
    del obj["subject"]["receipt_type"]
    with pytest.raises(SchemaError):
        _u(obj)
