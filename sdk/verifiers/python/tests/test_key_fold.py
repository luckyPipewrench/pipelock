# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest

from pipelock_aarp_verify.key_fold import reject_folded_pairs
from pipelock_aarp_verify.number import IJSONNumber, parse_json_strict
from pipelock_aarp_verify.receipt import ReceiptError, _reject_duplicate_pairs


def test_json_key_fold_shared_parity():
    fixture = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "conformance/testdata/json-key-folding.json"
        ).read_text()
    )
    for group in fixture["groups"]:
        for char in group[1:]:
            raw = json.dumps({group[0]: 1, char: 2})
            with pytest.raises(ValueError, match="duplicate object key"):
                json.loads(raw, object_pairs_hook=reject_folded_pairs)
            # Free-form maps retain both spellings and values; typed consumers
            # apply the folded schema check separately.
            assert parse_json_strict(raw) == {
                group[0]: IJSONNumber("1"),
                char: IJSONNumber("2"),
            }
            assert json.loads(raw, object_pairs_hook=_reject_duplicate_pairs) == {
                group[0]: 1,
                char: 2,
            }
    for entry in fixture["cases"]:
        if entry["valid"]:
            json.loads(entry["raw"], object_pairs_hook=reject_folded_pairs)
            parse_json_strict(entry["raw"])
        else:
            with pytest.raises(ValueError, match="duplicate object key"):
                json.loads(entry["raw"], object_pairs_hook=reject_folded_pairs)


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"nested":{"a":1,"a":2}}'])
def test_generic_key_parsers_reject_exact_duplicates(raw):
    with pytest.raises(ValueError, match="duplicate key"):
        parse_json_strict(raw)
    with pytest.raises(ReceiptError, match="duplicate object key"):
        json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
