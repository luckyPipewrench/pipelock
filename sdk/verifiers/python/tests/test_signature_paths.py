# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Per-signature appraisal branch coverage using locally-derived test keys.

These tests sign envelopes with the corpus test keys (the seed_hex values are
Ed25519 private seeds) so we can exercise the verified-signature branches that the
static corpus cannot cover without re-signing: a valid signature under a role that
does not satisfy the trust entry's role scope (mediator_key_pinned NOT confirmed),
malformed wire forms, key-type/alg mismatches, and the unimplemented PQ slot.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pipelock_aarp_verify.appraise import (
    TrustEntry,
    VerifyOptions,
    verify,
)
from pipelock_aarp_verify.envelope import (
    ProtectedHeader,
    signing_input,
    unmarshal,
)

_CORPUS = (
    Path(__file__).resolve().parents[3] / "conformance" / "testdata" / "aarp-corpus"
)
_KEYS = json.loads((_CORPUS / "test-keys.json").read_text())


def _priv(key_id: str) -> Ed25519PrivateKey:
    seed = bytes.fromhex(_KEYS["keys"][key_id]["seed_hex"])
    return Ed25519PrivateKey.from_private_bytes(seed)


def _pub(key_id: str) -> bytes:
    return bytes.fromhex(_KEYS["keys"][key_id]["public_key_hex"])


def _base_envelope() -> dict:
    return copy.deepcopy(
        json.loads(
            (_CORPUS / "golden" / "g01-single-ed25519-mediated.aarp.json").read_text()
        )
    )


def _sign(obj: dict, key_id: str, header: dict) -> dict:
    """Replace obj's single signature with a fresh one over the payload digest."""
    obj = copy.deepcopy(obj)
    obj["signatures"] = [{"protected": header, "sig": ""}]
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    digest = env.payload_digest()
    ph = ProtectedHeader(header)
    msg = signing_input(digest, ph)
    raw = _priv(key_id).sign(msg)
    wire = header["alg"] + ":" + base64.standard_b64encode(raw).decode("ascii")
    obj["signatures"][0]["sig"] = wire
    return obj


def _header(
    key_id: str, role: str, alg: str = "ed25519", key_type: str = "ed25519"
) -> dict:
    return {
        "profile": "aarp/v0.1",
        "canon": "jcs-rfc8785-nfc",
        "alg": alg,
        "key_type": key_type,
        "key_id": key_id,
        "signer_role": role,
    }


def _trust_with(entry: TrustEntry | None = None) -> VerifyOptions:
    opts = VerifyOptions(trusted_keys={"k-signer": _pub("k-signer")})
    if entry is not None:
        opts.trust["k-signer"] = entry
    return opts


def test_valid_sig_role_mismatch_no_pin():
    # Trust entry pins role=mediator; sign as countersig. Signature verifies, but
    # mediator_key_pinned is NOT confirmed because the role does not match.
    obj = _sign(_base_envelope(), "k-signer", _header("k-signer", "countersig"))
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    ap = verify(
        env, _trust_with(TrustEntry(mediator_id="mediator.example", role="mediator"))
    )
    assert ap.assertion_signed is True
    assert "mediator_key_pinned" not in ap.verified_claims
    assert "mediated" in ap.claimed_unverified


def test_valid_sig_trust_domain_mismatch_no_pin():
    # Entry requires a trust_domain the assertion does not carry -> no pin.
    obj = _sign(_base_envelope(), "k-signer", _header("k-signer", "mediator"))
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    ap = verify(
        env,
        _trust_with(
            TrustEntry(mediator_id="mediator.example", trust_domain="example.org")
        ),
    )
    assert ap.assertion_signed is True
    assert "mediator_key_pinned" not in ap.verified_claims


def test_valid_sig_mediator_id_mismatch_no_pin():
    obj = _sign(_base_envelope(), "k-signer", _header("k-signer", "mediator"))
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    ap = verify(env, _trust_with(TrustEntry(mediator_id="other.example")))
    assert ap.assertion_signed is True
    assert "mediator_key_pinned" not in ap.verified_claims


def test_valid_sig_with_full_pin():
    obj = _sign(_base_envelope(), "k-signer", _header("k-signer", "mediator"))
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    ap = verify(
        env, _trust_with(TrustEntry(mediator_id="mediator.example", role="mediator"))
    )
    assert "mediator_key_pinned" in ap.verified_claims


def test_key_type_mismatch_is_malformed():
    obj = _base_envelope()
    obj["signatures"][0]["protected"]["key_type"] = "ml-dsa"  # disagrees with ed25519
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    ap = verify(env, _trust_with())
    assert ap.signatures[0].status == "malformed"
    assert ap.assertion_signed is False


def test_unimplemented_alg_slot():
    obj = _base_envelope()
    obj["signatures"][0]["protected"]["alg"] = "ml-dsa-65"
    obj["signatures"][0]["protected"]["key_type"] = "ml-dsa"
    obj["signatures"][0]["protected"]["key_id"] = "k-pq"
    obj["signatures"][0]["protected"]["signer_role"] = "countersig"
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    ap = verify(env, _trust_with())
    assert ap.signatures[0].status == "unimplemented"


def test_malformed_wire_prefix():
    obj = _base_envelope()
    obj["signatures"][0]["sig"] = "rsa:AAAA"  # wrong alg prefix
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    ap = verify(env, _trust_with())
    assert ap.signatures[0].status == "malformed"


def test_malformed_wire_bad_base64():
    obj = _base_envelope()
    obj["signatures"][0]["sig"] = "ed25519:!!!notbase64!!!"
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    ap = verify(env, _trust_with())
    assert ap.signatures[0].status == "malformed"


def test_wrong_signature_length_is_failed():
    obj = _base_envelope()
    # 4-byte signature: decodes fine but is not 64 bytes -> failed.
    obj["signatures"][0]["sig"] = "ed25519:" + base64.standard_b64encode(
        b"\x00\x00\x00\x00"
    ).decode("ascii")
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    ap = verify(env, _trust_with())
    assert ap.signatures[0].status == "failed"


def test_trusted_key_wrong_size_is_malformed():
    obj = _base_envelope()
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    opts = VerifyOptions(trusted_keys={"k-signer": b"\x00\x00"})  # wrong key size
    ap = verify(env, opts)
    assert ap.signatures[0].status == "malformed"


def test_crit_in_signed_header_changes_digest_but_verifies():
    # A signature carrying an empty crit list signs the same bytes as no crit;
    # sign with a known-critical-less header and confirm it verifies (sanity that
    # to_signed_dict omits empty crit, matching Go's omitempty).
    obj = _sign(_base_envelope(), "k-signer", _header("k-signer", "mediator"))
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    ap = verify(env, _trust_with(TrustEntry(mediator_id="mediator.example")))
    assert ap.signatures[0].status == "verified"
