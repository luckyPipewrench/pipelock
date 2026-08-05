# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Shared evidence-provenance transform corpus gate."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import unicodedata2

from pipelock_aarp_verify.provenance import (
    UNICODE_VERSION,
    ProvenanceError,
    Recipe,
    supported_operation_kinds,
)

CORPUS = (
    Path(__file__).resolve().parents[3]
    / "conformance"
    / "testdata"
    / "transform-profile"
    / "evidence-provenance-v1.json"
)


def test_evidence_provenance_uses_profile_pinned_unicode_database() -> None:
    assert unicodedata2.unidata_version == UNICODE_VERSION == "15.0.0"


def test_html_entity_decode_iterates_non_common_named_entity() -> None:
    recipe = Recipe.from_json(
        "sha256:49f44e3056be677c48e8177b844576ba10c50c452f70dac77aef516e231dd316",
        [{"kind": "html_entity_decode"}],
    )
    assert recipe.apply("&amp;CounterClockwiseContourIntegral;") == "∳"


def test_evidence_provenance_transform_corpus() -> None:
    corpus = json.loads(CORPUS.read_text())
    assert corpus["format"] == "pipelock-evidence-transform-corpus/v1"
    covered: set[str] = set()
    errors: set[str] = set()
    for vector in corpus["vectors"]:
        recipe = Recipe.from_json(
            vector.get("transform_profile_digest", corpus["profile_digest"]),
            vector.get("recipe", []),
        )
        try:
            output = recipe.apply_bytes(
                base64.b64decode(vector["input_b64"], validate=True)
            )
        except ProvenanceError as exc:
            assert vector.get("want_error"), f"{vector['id']}: {exc}"
            assert vector["want_error"] in str(exc), vector["id"]
            for code in vector.get("errors", []):
                assert corpus["error_definitions"][code] in str(exc)
                errors.add(code)
        else:
            assert not vector.get("errors"), vector["id"]
            assert output.encode() == base64.b64decode(
                vector["output_b64"], validate=True
            )
            covered.update(op["kind"] for op in vector.get("recipe", []))
        assert set(vector.get("operations", [])) == {
            op["kind"]
            for op in vector.get("recipe", [])[: len(vector.get("operations", []))]
        }
    assert (
        covered == set(supported_operation_kinds()) == set(corpus["operation_coverage"])
    )
    assert errors == set(corpus["error_coverage"])
