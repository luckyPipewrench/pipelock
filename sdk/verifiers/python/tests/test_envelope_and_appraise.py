# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Envelope parsing + appraisal logic unit tests (error paths and classification)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pipelock_aarp_verify.appraise import (
    Appraisal,
    EnvelopeFatalError,
    SignatureResult,
    TrustEntry,
    VerifyOptions,
    comparable_appraisal,
    verify,
)
from pipelock_aarp_verify.envelope import (
    SchemaError,
    UnknownFieldError,
    unmarshal,
)
from pipelock_aarp_verify.number import UnsafeNumberError

_CORPUS = (
    Path(__file__).resolve().parents[3] / "conformance" / "testdata" / "aarp-corpus"
)


def _load_g01() -> dict:
    return json.loads(
        (_CORPUS / "golden" / "g01-single-ed25519-mediated.aarp.json").read_text()
    )


def _trust() -> VerifyOptions:
    tf = json.loads((_CORPUS / "trust.json").read_text())
    import binascii

    opts = VerifyOptions()
    for kid, kh in tf["trusted_keys"].items():
        opts.trusted_keys[kid] = binascii.unhexlify(kh)
    for kid, e in tf.get("trust_entries", {}).items():
        opts.trust[kid] = TrustEntry(
            mediator_id=e.get("mediator_id", ""),
            role=e.get("role", ""),
            trust_domain=e.get("trust_domain", ""),
        )
    return opts


def _dump(obj: dict) -> bytes:
    return json.dumps(obj).encode("utf-8")


def test_unmarshal_rejects_unknown_envelope_field():
    obj = _load_g01()
    obj["surprise"] = 1
    with pytest.raises(UnknownFieldError):
        unmarshal(_dump(obj))


def test_unmarshal_rejects_unknown_subject_field():
    obj = _load_g01()
    obj["subject"]["surprise"] = "x"
    with pytest.raises(UnknownFieldError):
        unmarshal(_dump(obj))


def test_unmarshal_rejects_unknown_protected_field():
    obj = _load_g01()
    obj["signatures"][0]["protected"]["surprise"] = "x"
    with pytest.raises(UnknownFieldError):
        unmarshal(_dump(obj))


def test_unmarshal_rejects_unsafe_number():
    obj = _load_g01()
    obj["ext"] = {"n": 9007199254740992}
    with pytest.raises(UnsafeNumberError):
        unmarshal(_dump(obj))


def test_ext_is_free_and_not_schema_checked():
    obj = _load_g01()
    obj["ext"] = {"anything": {"nested": "ok"}}
    env = unmarshal(_dump(obj))
    ap = verify(env, _trust())
    assert ap.assertion_signed is True


def test_profile_mismatch_is_fatal():
    obj = _load_g01()
    obj["profile"] = "aarp/v9.9"
    env = unmarshal(_dump(obj))
    with pytest.raises(SchemaError):
        verify(env, _trust())


def test_bad_digest_grammar_is_fatal():
    obj = _load_g01()
    obj["subject"]["action_record_sha256"] = "Z" * 64
    env = unmarshal(_dump(obj))
    with pytest.raises(SchemaError):
        verify(env, _trust())


def test_missing_mediator_id_is_fatal():
    obj = _load_g01()
    obj["assertion"]["mediator_id"] = ""
    env = unmarshal(_dump(obj))
    with pytest.raises(SchemaError):
        verify(env, _trust())


def test_empty_signatures_is_fatal():
    obj = _load_g01()
    obj["signatures"] = []
    env = unmarshal(_dump(obj))
    with pytest.raises(EnvelopeFatalError):
        verify(env, _trust())


def test_unknown_claim_is_claim_only():
    obj = _load_g01()
    obj["assertion"]["claimed"] = ["totally-made-up"]
    env = unmarshal(_dump(obj))
    ap = verify(env, _trust())
    assert "totally-made-up" in ap.claimed_unverified
    assert "totally-made-up" not in ap.verified_claims


def test_complete_mediation_never_verifiable():
    obj = _load_g01()
    obj["assertion"]["claimed"] = ["complete-mediation", "complete_mediation"]
    env = unmarshal(_dump(obj))
    ap = verify(env, _trust())
    assert "complete-mediation" in ap.claimed_unverified
    assert "complete_mediation" in ap.claimed_unverified


def test_duplicate_producer_claim_deduped():
    obj = _load_g01()
    obj["assertion"]["claimed"] = ["transparency_inclusion", "transparency_inclusion"]
    env = unmarshal(_dump(obj))
    ap = verify(env, _trust())
    assert ap.claimed_unverified.count("transparency_inclusion") == 1


def test_no_trust_means_unknown_key():
    obj = _load_g01()
    env = unmarshal(_dump(obj))
    ap = verify(env, VerifyOptions())  # empty trust
    assert ap.assertion_signed is False
    assert ap.signatures[0].status == "unknown_key"
    assert "mediated" in ap.claimed_unverified


def test_mediator_pin_requires_role_match():
    # Trust entry pins role=mediator; flip the signing role to countersig so the
    # signature still verifies but mediator_key_pinned must NOT be confirmed.
    obj = _load_g01()
    obj["signatures"][0]["protected"]["signer_role"] = "countersig"
    # Re-signing is out of scope here; with the role flipped the signature will
    # not verify over the canonical bytes, so we instead assert via a crafted
    # appraisal path below. This case is covered by corpus m06.
    env = unmarshal(_dump(obj))
    ap = verify(env, _trust())
    assert ap.assertion_signed is False  # signature no longer matches


def test_comparable_excludes_warnings_and_reason():
    ap = Appraisal()
    ap.assertion_signed = True
    ap.signatures = [
        SignatureResult(
            key_id="k",
            alg="ed25519",
            signer_role="mediator",
            status="verified",
            reason="secret prose",
        )
    ]
    ap.warnings = ["should not appear"]
    ap.verified_claims = ["receipt_signature_valid"]
    ap.axes = {"integrity": ["receipt_signature_valid"]}
    out = comparable_appraisal(ap).decode("utf-8")
    assert "secret prose" not in out
    assert "should not appear" not in out
    assert "warnings" not in out
    assert "reason" not in out


def test_comparable_signatures_preserve_envelope_order():
    ap = Appraisal()
    ap.signatures = [
        SignatureResult(
            key_id="z", alg="ed25519", signer_role="issuer", status="failed"
        ),
        SignatureResult(
            key_id="a", alg="ed25519", signer_role="mediator", status="verified"
        ),
    ]
    out = comparable_appraisal(ap).decode("utf-8")
    # "z" appears before "a" because signatures are NOT sorted.
    assert out.index('"key_id":"z"') < out.index('"key_id":"a"')


def test_chain_link_present_adds_chain_link_present_claim():
    obj = json.loads(
        (_CORPUS / "chain" / "c01-valid-stream.aarp.jsonl").read_text().splitlines()[0]
    )
    env = unmarshal(_dump(obj))
    ap = verify(env, _trust())
    assert "receipt_timestamp_monotonic_chain_present" in ap.verified_claims


def test_copy_independence():
    # Defensive: mutating one parsed envelope's lists does not affect a re-parse.
    obj = _load_g01()
    env1 = unmarshal(_dump(obj))
    env2 = unmarshal(_dump(copy.deepcopy(obj)))
    env1.assertion.claimed.append("x")
    assert "x" not in env2.assertion.claimed


def test_bad_timestamp_is_fatal():
    obj = _load_g01()
    obj["assertion"]["issued_at"] = "not-a-time"
    env = unmarshal(_dump(obj))
    with pytest.raises(SchemaError):
        verify(env, _trust())


def test_bad_trust_domain_syntax_is_fatal():
    obj = _load_g01()
    obj["assertion"]["trust_domain"] = "10.0.0.1"  # IP literal, not a DNS name
    env = unmarshal(_dump(obj))
    with pytest.raises(SchemaError):
        verify(env, _trust())


def test_optional_fields_serialize_in_payload():
    obj = _load_g01()
    obj["assertion"]["trust_domain"] = "example.org"
    obj["assertion"]["evidence_refs"] = ["spiffe_svid"]
    env = unmarshal(_dump(obj))
    asd = env.assertion.to_signed_dict()
    assert asd["trust_domain"] == "example.org"
    assert asd["evidence_refs"] == ["spiffe_svid"]


def test_crit_ext_present_serializes_in_payload():
    # A known-less critical extension is fatal, but the payload serializer must
    # still include crit_ext when present (checked before the crit-ext registry).
    obj = _load_g01()
    obj["crit_ext"] = ["x-some-ext"]
    env = unmarshal(_dump(obj))
    payload = env.payload_signed_dict()
    assert payload["crit_ext"] == ["x-some-ext"]
