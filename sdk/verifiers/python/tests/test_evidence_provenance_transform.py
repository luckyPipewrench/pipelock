# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Shared evidence-provenance transform corpus gate."""

from __future__ import annotations

import base64
import json
import unicodedata
from pathlib import Path

import pytest

from pipelock_aarp_verify.provenance import (
    PROFILE_DIGEST,
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
    assert unicodedata.unidata_version == UNICODE_VERSION == "15.0.0"


def test_lowercase_does_not_adopt_post_profile_case_mappings() -> None:
    recipe = Recipe.from_json(PROFILE_DIGEST, [{"kind": "lowercase"}])
    assert recipe.apply("\u1c89") == "\u1c89"


def test_recipe_limits_reject_unbounded_verifier_work() -> None:
    with pytest.raises(ProvenanceError, match="exceeds 32 operations"):
        Recipe.from_json(PROFILE_DIGEST, [{"kind": "identity"}] * 33).validate()

    token = "%" + "25" * 500
    recipe = Recipe.from_json(PROFILE_DIGEST, [{"kind": "query_unescape"}])
    with pytest.raises(ProvenanceError, match="cumulative processing budget"):
        recipe.apply(token * 1500)


@pytest.mark.parametrize("kind", ["base32_decode_liberal", "base64_decode_liberal"])
def test_unpadded_liberal_decoders_reject_existing_padding(kind: str) -> None:
    operation: dict[str, object] = {"kind": kind, "decode_padding": False}
    value = "MZ======"
    if kind == "base64_decode_liberal":
        operation["alphabet"] = "standard"
        value = "TQ=="
    recipe = Recipe.from_json(PROFILE_DIGEST, [operation])
    with pytest.raises(ProvenanceError, match="unexpected padding"):
        recipe.apply(value)


def test_html_entity_decode_iterates_non_common_named_entity() -> None:
    recipe = Recipe.from_json(
        PROFILE_DIGEST,
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


@pytest.mark.parametrize(
    ("digest", "operations", "error"),
    [
        (None, [], "missing transform profile digest"),
        ("bad", [], "invalid SHA-256 digest"),
        ("sha256:" + "0" * 64, [], "unknown profile"),
        (PROFILE_DIGEST, None, "operations must be an array"),
        (PROFILE_DIGEST, [{"kind": "identity", "extra": 1}], "unknown operation field"),
        (
            PROFILE_DIGEST,
            [{"kind": "url_component", "component": "port"}],
            "unknown URL component",
        ),
        (
            PROFILE_DIGEST,
            [{"kind": "url_component", "component": "path", "selector": "x"}],
            "unsupported selector",
        ),
        (
            PROFILE_DIGEST,
            [{"kind": "base64_decode_liberal", "alphabet": "other"}],
            "unknown base64 alphabet",
        ),
        (
            PROFILE_DIGEST,
            [{"kind": "encoded_token_normalize", "alphabet": "other"}],
            "unknown encoded-token alphabet",
        ),
        (
            PROFILE_DIGEST,
            [{"kind": "query_subsequence", "indices": [1, 1]}],
            "strictly increasing",
        ),
        (
            PROFILE_DIGEST,
            [{"kind": "encoded_run", "minimum_length": 0}],
            "must be positive",
        ),
        (
            PROFILE_DIGEST,
            [{"kind": "percent_decode"}],
            "percent decode passes must be 1..4",
        ),
        (
            PROFILE_DIGEST,
            [{"kind": "identity", "occurrence": 0}],
            "unsupported occurrence",
        ),
        (
            PROFILE_DIGEST,
            [{"kind": "text_segment", "occurrence": -1}],
            "unsigned integer",
        ),
        (
            PROFILE_DIGEST,
            [{"kind": "base64_decode", "decode_padding": 1}],
            "must be boolean",
        ),
    ],
)
def test_recipe_validation_boundaries(
    digest: object, operations: object, error: str
) -> None:
    with pytest.raises(ProvenanceError, match=error):
        Recipe.from_json(digest, operations).validate()


@pytest.mark.parametrize(
    ("component", "expected"),
    [
        ("url", "https://api.vendor.example/a/b?x=y"),
        ("hostname", "api.vendor.example"),
        ("path", "/a/b"),
        ("raw_query", "x=y"),
    ],
)
def test_url_component_surfaces(component: str, expected: str) -> None:
    recipe = Recipe.from_json(
        PROFILE_DIGEST, [{"kind": "url_component", "component": component}]
    )
    assert recipe.apply("https://api.vendor.example/a/b?x=y") == expected


def test_liberal_hex_rejects_non_utf8_output() -> None:
    recipe = Recipe.from_json(PROFILE_DIGEST, [{"kind": "hex_decode_liberal"}])
    with pytest.raises(ProvenanceError, match="invalid UTF-8"):
        recipe.apply("ff")


@pytest.mark.parametrize(
    ("operation", "value", "label"),
    [
        ({"kind": "hex_decode_liberal"}, "gg", "liberal hex decode"),
        (
            {"kind": "base32_decode_liberal", "decode_padding": False},
            "!",
            "liberal base32 decode",
        ),
        (
            {
                "kind": "base64_decode_liberal",
                "alphabet": "standard",
                "decode_padding": False,
            },
            "!",
            "liberal base64 decode",
        ),
    ],
)
def test_liberal_decode_errors_name_the_operation(
    operation: dict[str, object], value: str, label: str
) -> None:
    recipe = Recipe.from_json(PROFILE_DIGEST, [operation])
    with pytest.raises(ProvenanceError, match=label):
        recipe.apply(value)
