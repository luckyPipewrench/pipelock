# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for the experimental fixture-only provenance command."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pipelock_aarp_verify.number import parse_json_strict
from pipelock_aarp_verify.provenance_proof import (
    FIXTURE_FORMAT,
    PROFILE_DIGEST,
    ProvenanceError,
    _apply_recipe,
    _commit,
    _recipe_bytes,
    _validate_intervals,
    verify_fixture,
)

_TRANSFORM_CORPUS = (
    Path(__file__).resolve().parents[3]
    / "conformance"
    / "testdata"
    / "transform-profile"
    / "evidence-provenance-v1.json"
)


def _fixture(
    *,
    critical: list[str] | None = None,
    span: tuple[int, int] = (1, 5),
    chain_length: int = 1,
    break_chain: bool = False,
    producer: dict[str, str] | None = None,
    verification_artifacts: dict[str, str] | None = None,
    missing_first_source_with_bad_second: bool = False,
    overflow_occurrence: bool = False,
    duplicate_chain_seq: bool = False,
    match_class: str = "credential",
) -> bytes:
    key = bytes(range(32))
    source = "A💩B".encode()
    operations = [{"kind": "identity"}]
    if overflow_occurrence:
        operations = [
            {
                "kind": "url_component",
                "component": "query_value",
                "selector": "q",
                "occurrence": 1 << 32,
            }
        ]
    recipe = {
        "transform_profile_digest": PROFILE_DIGEST,
        "operations": operations,
    }
    commitment_recipe = {
        "transform_profile_digest": PROFILE_DIGEST,
        "operations": [{"kind": "identity"}],
    }
    # The overflow recipe must remain parseable JSON but cannot be framed as a
    # uint32. Commitments are irrelevant because proof-structure validation
    # must reject it before any opening is attempted.
    strict_commitment_recipe = parse_json_strict(json.dumps(commitment_recipe).encode())
    recipe_bytes = _recipe_bytes(strict_commitment_recipe)
    view_commitment = _commit(
        key,
        "pipelock/evidence-provenance/view/v1",
        [
            (1).to_bytes(8, "big"),
            b"source",
            PROFILE_DIGEST.encode(),
            recipe_bytes,
            source,
        ],
    )
    match_commitment = _commit(
        key,
        "pipelock/evidence-provenance/match/v1",
        [
            b"source",
            PROFILE_DIGEST.encode(),
            recipe_bytes,
            view_commitment.encode(),
            (1).to_bytes(8, "big"),
            span[0].to_bytes(8, "big"),
            span[1].to_bytes(8, "big"),
            match_class.encode(),
        ],
    )
    proof_sources = [
        {
            "source_ordinal": 1,
            "source_id": "source",
            "recipe": recipe,
            "view_commitment": view_commitment,
            "matches": [
                {
                    "match_ordinal": 1,
                    "byte_start": span[0],
                    "byte_end": span[1],
                    "match_class": match_class,
                    "match_commitment": match_commitment,
                }
            ],
        }
    ]
    source_inputs = [
        {
            "source_id": "source",
            "bytes_b64": base64.b64encode(source).decode(),
        }
    ]
    if missing_first_source_with_bad_second:
        proof_sources.append(
            {
                "source_ordinal": 2,
                "source_id": "available",
                "recipe": recipe,
                "view_commitment": "hmac-sha256:" + "0" * 64,
                "matches": [
                    {
                        "match_ordinal": 1,
                        "byte_start": span[0],
                        "byte_end": span[1],
                        "match_class": "credential",
                        "match_commitment": match_commitment,
                    }
                ],
            }
        )
        source_inputs = [
            {
                "source_id": "available",
                "bytes_b64": base64.b64encode(source).decode(),
            }
        ]
    proof = {
        "version": "pipelock-evidence-provenance-proof/v1",
        "transform_profile_digest": PROFILE_DIGEST,
        "sources": proof_sources,
        "producer": {} if producer is None else producer,
    }
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    entries = []
    previous = None
    for sequence in range(chain_length):
        signed = json.dumps(
            {
                "chain_seq": sequence,
                "chain_prev_hash": (
                    "genesis"
                    if previous is None or (break_chain and sequence == 1)
                    else "sha256:" + hashlib.sha256(previous).hexdigest()
                ),
                "critical_features": ["evidence_provenance"]
                if critical is None
                else critical,
                "proof": proof,
            },
            separators=(",", ":"),
        ).encode()
        if duplicate_chain_seq:
            signed = signed.replace(
                b'{"chain_seq":0,', b'{"chain_seq":0,"chain_seq":0,', 1
            )
        entries.append(
            {
                "signed_b64": base64.b64encode(signed).decode(),
                "signature": "ed25519:" + private.sign(signed).hex(),
            }
        )
        previous = signed
    verification = {
        "signer_public_key_hex": public.hex(),
        "commitment_key_hex": key.hex(),
        "sources": source_inputs,
    }
    if verification_artifacts is not None:
        verification.update(verification_artifacts)
    return json.dumps(
        {
            "format": FIXTURE_FORMAT,
            "entries": entries,
            "verification": verification,
        },
        separators=(",", ":"),
    ).encode()


def test_fixture_verifies_available_stages_but_is_incomplete_without_source_commitment() -> (
    None
):
    output, exit_code = verify_fixture(_fixture())
    assert exit_code == 0
    assert output == {
        "trust_roots": "fixture supplied; self-attested; not authenticated",
        "authenticated_provenance": False,
        "signature": "verified",
        "chain": "verified",
        "artifacts": "matched",
        "source_commitment": "not_checked",
        "view_reproduction": "reproduced",
        "location": "exact_coordinates",
        "match_commitment": "opened",
        "overall": "incomplete",
    }


def test_fixture_rejects_unknown_critical_feature_at_its_own_stage() -> None:
    output, exit_code = verify_fixture(_fixture(critical=["other"]))
    assert exit_code == 1
    assert output["signature"] == "verified"
    assert output["chain"] == "verified"
    assert output["failure_stage"] == "critical_features"


def test_fixture_rejects_utf8_boundary_at_location_stage() -> None:
    output, exit_code = verify_fixture(_fixture(span=(2, 5)))
    assert exit_code == 1
    assert output["view_reproduction"] == "reproduced"
    assert output["failure_stage"] == "location"


def test_fixture_rejects_occurrence_above_uint32_as_proof_structure() -> None:
    output, exit_code = verify_fixture(_fixture(overflow_occurrence=True))
    assert exit_code == 1
    assert output["failure_stage"] == "proof_structure"


def test_fixture_rejects_empty_match_class_as_proof_structure() -> None:
    output, exit_code = verify_fixture(_fixture(match_class=""))
    assert exit_code == 1
    assert output["failure_stage"] == "proof_structure"


def test_fixture_rejects_duplicate_keys_in_envelope_and_signed_payload() -> None:
    envelope = _fixture().replace(b'{"format":', b'{"format":"duplicate","format":', 1)
    envelope_output, envelope_exit = verify_fixture(envelope)
    assert envelope_exit == 1
    assert envelope_output["failure_stage"] == "proof_structure"

    signed_output, signed_exit = verify_fixture(_fixture(duplicate_chain_seq=True))
    assert signed_exit == 1
    assert signed_output["failure_stage"] == "proof_structure"


def test_fixture_rejects_empty_entries_as_proof_structure() -> None:
    output, exit_code = verify_fixture(_fixture(chain_length=0))
    assert exit_code == 1
    assert output["failure_stage"] == "proof_structure"


def test_fixture_checks_every_chain_entry() -> None:
    output, exit_code = verify_fixture(_fixture(chain_length=2, break_chain=True))
    assert exit_code == 1
    assert output["signature"] == "verified"
    assert output["failure_stage"] == "chain"


def test_artifact_mismatch_outranks_an_unavailable_sibling_attestation() -> None:
    output, exit_code = verify_fixture(
        _fixture(
            producer={
                "binary_digest": "sha256:" + hashlib.sha256(b"expected").hexdigest(),
                "ruleset_digest": "sha256:" + hashlib.sha256(b"ruleset").hexdigest(),
            },
            verification_artifacts={
                "binary_b64": base64.b64encode(b"wrong").decode(),
            },
        )
    )
    assert exit_code == 1
    assert output["artifacts"] == "mismatch"
    assert output["failure_stage"] == "artifacts"


def test_missing_source_does_not_hide_later_available_source_mismatch() -> None:
    output, exit_code = verify_fixture(
        _fixture(missing_first_source_with_bad_second=True)
    )
    assert exit_code == 1
    assert output["view_reproduction"] == "not_checked"
    assert output["location"] == "not_checked"
    assert output["match_commitment"] == "mismatch"
    assert output["failure_stage"] == "view_commitment"


def test_transform_corpus_vectors_are_byte_exact() -> None:
    """The Python port executes every normative recipe vector directly."""
    corpus = json.loads(_TRANSFORM_CORPUS.read_text())
    assert len(corpus["vectors"]) == 63
    for vector in corpus["vectors"]:
        recipe = {
            "transform_profile_digest": vector.get(
                "transform_profile_digest", PROFILE_DIGEST
            ),
            "operations": vector.get("recipe") or [],
        }
        strict_recipe = parse_json_strict(json.dumps(recipe).encode())
        input_bytes = base64.b64decode(vector["input_b64"])
        want_error = vector.get("want_error", "")
        if want_error:
            with pytest.raises(ProvenanceError, match=re.escape(want_error)):
                _apply_recipe(strict_recipe, input_bytes)
            continue
        assert _apply_recipe(strict_recipe, input_bytes) == base64.b64decode(
            vector["output_b64"]
        ), vector["id"]


def test_interval_corpus_vectors_are_byte_exact() -> None:
    """Every profile interval edge is checked as UTF-8 byte coordinates."""
    corpus = json.loads(_TRANSFORM_CORPUS.read_text())
    assert len(corpus["interval_vectors"]) == 8
    for vector in corpus["interval_vectors"]:
        view = base64.b64decode(vector["view_b64"])
        matches = [tuple(bounds) for bounds in vector["matches"]]
        want_error = vector["want_error"]
        if want_error:
            with pytest.raises(ProvenanceError, match=re.escape(want_error)):
                _validate_intervals(view, matches)
            continue
        _validate_intervals(view, matches)
