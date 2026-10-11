# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest

from pipelock_aarp_verify.key_fold import reject_folded_pairs
from pipelock_aarp_verify.number import parse_json_strict
from pipelock_aarp_verify.receipt import _reject_duplicate_pairs


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
            parse_json_strict(raw)
            json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    for entry in fixture["cases"]:
        if entry["valid"]:
            json.loads(entry["raw"], object_pairs_hook=reject_folded_pairs)
            parse_json_strict(entry["raw"])
        else:
            with pytest.raises(ValueError, match="duplicate object key"):
                json.loads(entry["raw"], object_pairs_hook=reject_folded_pairs)
