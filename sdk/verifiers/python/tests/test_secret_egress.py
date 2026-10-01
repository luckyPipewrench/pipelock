# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Secret-egress contract parity, strict parsing, and signed-receipt regression tests."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pipelock_aarp_verify.canonical import canonicalize
from pipelock_aarp_verify.number import StrictParseError, parse_json_strict
from pipelock_aarp_verify.receipt import (
    ReceiptError,
    load_evidence_chain,
    load_receipt,
    normalize_evidence_receipt,
    receipt_hash,
    verify_evidence_chain,
    verify_evidence_receipt,
    verify_receipt_file,
)
from pipelock_aarp_verify.secret_egress import (
    SECRET_EGRESS_PAYLOAD_KIND,
    SecretEgressError,
    validate_decision,
)

ROOT = Path(__file__).resolve().parents[4]
CORPUS = ROOT / "sdk/conformance/testdata/secret-egress-v1"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"pipelock secret-egress-v1 conformance test key").digest()
)
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes_raw().hex()
REGISTRY_HASH = "sha256:" + "a" * 64


def _decision() -> dict[str, Any]:
    return {
        "version": 1,
        "action_id": "11111111-1111-4111-8111-111111111111",
        "decision_id": "22222222-2222-4222-8222-222222222222",
        "site_id": "proxy.forward.body.original",
        "plane": "proxy",
        "transport": "forward",
        "location": "body",
        "view": "original",
        "boundary": "upstream_request",
        "phase": "intent",
        "destination_kind": "network",
        "destination_ref": "api.vendor.example",
        "pattern_class": "core_floor",
        "rule_id": "builtin.credential",
        "finding_disposition": "block",
        "planned_byte_form": "none",
        "authorization": {"kind": "none"},
        "persistence_policy": "required_before_action",
    }


def _sign(receipt: dict[str, Any]) -> None:
    receipt["signature"] = {
        "signer_key_id": "",
        "key_purpose": "",
        "algorithm": "",
        "signature": "",
    }
    signature = PRIVATE_KEY.sign(canonicalize(receipt))
    receipt["signature"] = {
        "signer_key_id": PUBLIC_KEY,
        "key_purpose": "receipt-signing",
        "algorithm": "ed25519",
        "signature": "ed25519:" + signature.hex(),
    }


def _receipt() -> dict[str, Any]:
    receipt = json.loads(
        (
            ROOT
            / "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json"
        ).read_text()
    )
    receipt.update(
        payload_kind=SECRET_EGRESS_PAYLOAD_KIND,
        payload={"registry_hash": REGISTRY_HASH, "decision": _decision()},
        crit=["canonicalization", SECRET_EGRESS_PAYLOAD_KIND],
        chain_seq=0,
        chain_prev_hash="genesis",
    )
    _sign(receipt)
    return receipt


def _write(tmp_path: Path, receipt: dict[str, Any]) -> Path:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt, separators=(",", ":")))
    return path


def test_signed_secret_egress_receipt_verifies(tmp_path: Path) -> None:
    receipt = _receipt()
    verify_evidence_receipt(receipt, PUBLIC_KEY)
    report = verify_receipt_file(_write(tmp_path, receipt), PUBLIC_KEY)
    assert report["valid"] is True, report
    assert report["transport"] == "forward"
    action_id = receipt["payload"]["decision"]["action_id"]
    assert action_id != receipt["event_id"]
    assert report["action_id"] == action_id
    # A syntactically valid hash is not a membership assertion.
    receipt["payload"]["registry_hash"] = "sha256:" + "b" * 64
    _sign(receipt)
    verify_evidence_receipt(receipt, PUBLIC_KEY)


def test_shared_secret_egress_corpus() -> None:
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    assert manifest["version"] == 1
    assert manifest["cases"]
    for case in manifest["cases"]:
        result = verify_receipt_file(CORPUS / case["file"], manifest["public_key_hex"])
        assert result["valid"] is case["valid"], (case["name"], result)


@pytest.mark.parametrize("field", list(_decision()))
@pytest.mark.parametrize("mutation", ["missing", "null", "case", "unknown"])
def test_retained_decision_fields_are_exact_required_and_nonnull(
    field: str, mutation: str
) -> None:
    decision = _decision()
    if mutation == "missing":
        del decision[field]
    elif mutation == "null":
        decision[field] = None
    elif mutation == "case":
        decision[field.upper()] = decision.pop(field)
    else:
        decision["unexpected"] = decision[field]
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize("value", [None, [], "", False, True, 1.0, "1", 0, 2])
def test_version_requires_integer_one(value: Any) -> None:
    decision = _decision()
    decision["version"] = value
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize(
    "field", [k for k in _decision() if k not in {"version", "authorization"}]
)
@pytest.mark.parametrize("value", [[], {}, False, 17])
def test_string_fields_reject_other_types(field: str, value: Any) -> None:
    decision = _decision()
    decision[field] = value
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize("version", "12345678")
@pytest.mark.parametrize("variant", "89ab")
def test_uuid_accepted_versions_and_variants(version: str, variant: str) -> None:
    decision = _decision()
    decision["action_id"] = f"01234567-89ab-{version}def-{variant}123-456789abcdef"
    validate_decision(decision)


@pytest.mark.parametrize(
    "value",
    [
        "01234567-89ab-0def-8123-456789abcdef",
        "01234567-89ab-9def-8123-456789abcdef",
        "01234567-89ab-4def-7123-456789abcdef",
        "01234567-89AB-4def-8123-456789abcdef",
        "0123456789ab4def8123456789abcdef",
        "",
        "00000000-0000-0000-0000-000000000000",
    ],
)
def test_invalid_uuid(value: str) -> None:
    decision = _decision()
    decision["action_id"] = value
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


def test_distinct_identifiers() -> None:
    decision = _decision()
    decision["decision_id"] = decision["action_id"]
    with pytest.raises(SecretEgressError):
        validate_decision(decision)
    for name in ["action_id", "decision_id"]:
        receipt = _receipt()
        receipt["event_id"] = receipt["payload"]["decision"][name]
        with pytest.raises(ReceiptError):
            normalize_evidence_receipt(receipt)


@pytest.mark.parametrize(
    "transport,boundary",
    list(
        itertools.product(
            [
                "fetch",
                "forward",
                "connect",
                "intercept",
                "reverse",
                "websocket",
                "mcp_stdio",
                "mcp_http_upstream",
                "mcp_ws",
                "mcp_http_listener",
                "mcp_http",
                "mcp_websocket",
                "agent_hook",
                "unknown",
            ],
            [
                "upstream_request",
                "upstream_frame",
                "tunnel_admission",
                "tool_dispatch",
                "hook_decision",
                "unknown",
            ],
        )
    ),
)
def test_transport_boundary_matrix(transport: str, boundary: str) -> None:
    allowed = {
        "fetch": {"upstream_request"},
        "forward": {"upstream_request"},
        "connect": {"tunnel_admission"},
        "intercept": {"upstream_request"},
        "reverse": {"upstream_request"},
        "websocket": {"upstream_request", "upstream_frame"},
        "mcp_stdio": {"upstream_request", "tool_dispatch"},
        "mcp_http_upstream": {"upstream_request", "tool_dispatch"},
        "mcp_ws": {"upstream_request", "tool_dispatch"},
        "mcp_http_listener": {"upstream_request", "tool_dispatch"},
    }
    decision = _decision()
    decision.update(transport=transport, boundary=boundary)
    if transport == "mcp_stdio":
        decision.update(
            destination_kind="local_process", destination_ref="configured.server"
        )
    if boundary in allowed.get(transport, set()):
        validate_decision(decision)
    else:
        with pytest.raises(SecretEgressError):
            validate_decision(decision)


@pytest.mark.parametrize(
    "field,values",
    [
        ("location", ["url", "header", "body", "tool_arguments", "envelope", "frame"]),
        (
            "view",
            [
                "original",
                "normalized",
                "post_transform",
                "reassembled",
                "authorization",
            ],
        ),
        ("pattern_class", ["core_floor", "configured"]),
        ("persistence_policy", ["required_before_action", "best_effort"]),
    ],
)
def test_contract_enum_values(field: str, values: list[str]) -> None:
    for value in values:
        decision = _decision()
        decision[field] = value
        validate_decision(decision)
    decision[field] = "unexpected"
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize("field", ["site_id", "rule_id"])
@pytest.mark.parametrize(
    "value,valid",
    [
        ("A_b:c.d-9", True),
        ("a" * 128, True),
        ("a" * 129, False),
        ("", False),
        (" name", False),
        ("name ", False),
        ("name\n", False),
        ("é", False),
        ("https://api.vendor.example", False),
        ("header=value", False),
    ],
)
def test_symbolic_identifier_grammar(field: str, value: str, valid: bool) -> None:
    decision = _decision()
    decision[field] = value
    if valid:
        validate_decision(decision)
    else:
        with pytest.raises(SecretEgressError):
            validate_decision(decision)


@pytest.mark.parametrize(
    "host,valid",
    [
        ("api.vendor.example", True),
        ("a", True),
        ("localhost", True),
        ("a" * 63 + ".example", True),
        ("a" * 64 + ".example", False),
        ("a" * 63 + "." + "a" * 63 + "." + "a" * 63 + "." + "a" * 61, True),
        ("a" * 63 + "." + "a" * 63 + "." + "a" * 63 + "." + "a" * 62, False),
        ("a-b.example", True),
        ("-a.example", False),
        ("a-.example", False),
        ("api.vendor.example.", False),
        ("API.vendor.example", False),
        ("a..example", False),
        ("https://api.vendor.example", False),
        ("api.vendor.example:443", False),
        ("a_b.example", False),
        ("", False),
        (" a.example", False),
        ("a.example\n", False),
        ("127.0.0.1", True),
        ("0.0.0.0", True),
        ("255.255.255.255", True),
        ("2001:db8::1", True),
        ("::", True),
        ("::1", True),
        ("fe80::1", True),
        ("::ffff:192.0.2.1", False),
        ("::ffff:c000:201", False),
        ("2001:0db8::1", False),
        ("2001:DB8::1", False),
        ("[2001:db8::1]", False),
        ("fe80::1%eth0", False),
        ("2001:db8:0:0:0:0:0:1", False),
        ("::192.0.2.1", False),
        ("0x7f000001", False),
        ("2130706433", False),
        ("0177.0.0.1", False),
        ("127.1", False),
        ("10.0.1", False),
        ("0000000000000", False),
        ("0x7f.0.0.1", False),
        ("127.0.0.01", False),
        ("127.0.0.1.", False),
        ("4294967296", False),
        ("999.999.999.999", False),
        ("0xnothex", True),
        ("123.api.vendor.example", True),
        ("0x.api.vendor.example", True),
        ("api.vendor.0xnothex", True),
        ("0x", False),
        ("0x100000000", False),
        ("api.vendor.123", False),
        ("api.vendor.0x", False),
        ("api.vendor.0xff", False),
        ("192.0.2.1.1", False),
        ("09", False),
        ("08.0.0.1", False),
        ("a.1", False),
    ],
)
def test_canonical_network_destinations_match_go(host: str, valid: bool) -> None:
    decision = _decision()
    decision["destination_ref"] = host
    if valid:
        validate_decision(decision)
    else:
        with pytest.raises(SecretEgressError):
            validate_decision(decision)


@pytest.mark.parametrize(
    "transport",
    [
        "forward",
        "mcp_stdio",
        "mcp_http_upstream",
        "mcp_ws",
        "mcp_http_listener",
        "mcp_http",
        "mcp_websocket",
    ],
)
def test_local_process_references(transport: str) -> None:
    decision = _decision()
    decision.update(
        transport=transport,
        destination_kind="local_process",
        destination_ref="upstream:configured",
    )
    if transport != "mcp_stdio":
        with pytest.raises(SecretEgressError):
            validate_decision(decision)
    else:
        validate_decision(decision)
        decision["destination_ref"] = "binary --secret=value"
        with pytest.raises(SecretEgressError):
            validate_decision(decision)


@pytest.mark.parametrize(
    "finding,planned",
    list(
        itertools.product(
            ["block", "redact", "observe", "authorize", "exempt"],
            ["none", "original", "transformed", "unknown"],
        )
    ),
)
def test_findings_and_planned_bytes(finding: str, planned: str) -> None:
    decision = _decision()
    decision.update(finding_disposition=finding, planned_byte_form=planned)
    if finding in {"authorize", "exempt"}:
        decision["authorization"] = {
            "kind": "authorization" if finding == "authorize" else "exemption",
            "ref": "credential.audience",
            "origin": "builtin",
        }
    valid = (
        planned != "unknown"
        and not (finding == "block" and planned != "none")
        and not (finding == "redact" and planned == "original")
    )
    if valid:
        validate_decision(decision)
    else:
        with pytest.raises(SecretEgressError):
            validate_decision(decision)


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {},
        {"Kind": "none"},
        {"kind": "None"},
        {"kind": "none", "ref": ""},
        {"kind": "none", "origin": ""},
        {"kind": "none", "ref": None},
        {"kind": "none", "extra": "x"},
        {"kind": "authorization", "ref": "allow", "origin": "builtin"},
    ],
)
def test_unauthorized_findings_require_exact_none(value: Any) -> None:
    decision = _decision()
    decision["authorization"] = value
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize("origin", ["builtin", "operator"])
@pytest.mark.parametrize(
    "kind,finding", [("authorization", "authorize"), ("exemption", "exempt")]
)
def test_named_authority_fields(origin: str, kind: str, finding: str) -> None:
    decision = _decision()
    decision.update(
        finding_disposition=finding,
        authorization={"kind": kind, "ref": "policy.rule", "origin": origin},
    )
    validate_decision(decision)
    for field in ["kind", "ref", "origin"]:
        for value in [None, "", "invalid value", [], {}]:
            changed = copy.deepcopy(decision)
            changed["authorization"][field] = value
            with pytest.raises(SecretEgressError):
                validate_decision(changed)
        changed = copy.deepcopy(decision)
        del changed["authorization"][field]
        with pytest.raises(SecretEgressError):
            validate_decision(changed)


@pytest.mark.parametrize(
    "reason",
    [
        "unparseable_body",
        "no_safe_raw_span",
        "unsupported_encoding",
        "unsupported_shape",
        "opaque_arguments",
    ],
)
@pytest.mark.parametrize("origin", ["builtin", "operator"])
def test_rewrite_fallback_is_independent_and_strict(reason: str, origin: str) -> None:
    decision = _decision()
    decision["rewrite_fallback"] = {
        "reason": reason,
        "policy_ref": "fallback.rule",
        "policy_origin": origin,
    }
    validate_decision(decision)
    for field in ["reason", "policy_ref", "policy_origin"]:
        for value in [None, "", "unknown value", [], {}]:
            changed = copy.deepcopy(decision)
            changed["rewrite_fallback"][field] = value
            with pytest.raises(SecretEgressError):
                validate_decision(changed)
        changed = copy.deepcopy(decision)
        del changed["rewrite_fallback"][field]
        with pytest.raises(SecretEgressError):
            validate_decision(changed)


@pytest.mark.parametrize(
    "release,byte_form",
    list(
        itertools.product(
            ["none", "partial", "complete", "unknown"],
            ["none", "original", "transformed", "unknown"],
        )
    ),
)
def test_observed_outcomes_do_not_have_to_match_intent(
    release: str, byte_form: str
) -> None:
    decision = _decision()
    decision.update(
        phase="outcome", outcome={"release": release, "byte_form": byte_form}
    )
    if (release == "none") == (byte_form == "none"):
        validate_decision(decision)
    else:
        with pytest.raises(SecretEgressError):
            validate_decision(decision)


@pytest.mark.parametrize(
    "phase,outcome",
    [
        ("intent", {"release": "none", "byte_form": "none"}),
        ("intent", None),
        ("outcome", None),
        ("outcome", {}),
        ("outcome", []),
        ("unknown", {"release": "none", "byte_form": "none"}),
        ("outcome", {"release": "wrong", "byte_form": "none"}),
        ("outcome", {"release": "none", "byte_form": "wrong"}),
        ("outcome", {"release": "none", "byte_form": None}),
        ("outcome", {"release": "none", "Byte_form": "none"}),
        ("outcome", {"release": "none", "byte_form": "none", "extra": 1}),
    ],
)
def test_invalid_outcome_shape_and_phase(phase: str, outcome: Any) -> None:
    decision = _decision()
    decision.update(phase=phase, outcome=outcome)
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


def test_outcome_phase_requires_observation() -> None:
    decision = _decision()
    decision["phase"] = "outcome"
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize("field", ["registry_hash", "decision"])
@pytest.mark.parametrize("mutation", ["missing", "null", "case", "unknown"])
def test_payload_exact_fields(field: str, mutation: str) -> None:
    receipt = _receipt()
    payload = receipt["payload"]
    if mutation == "missing":
        del payload[field]
    elif mutation == "null":
        payload[field] = None
    elif mutation == "case":
        payload[field.upper()] = payload.pop(field)
    else:
        payload["unexpected"] = 1
    with pytest.raises(ReceiptError):
        normalize_evidence_receipt(receipt)


@pytest.mark.parametrize(
    "hash_value", ["", "a" * 64, "sha256:" + "A" * 64, "sha256:" + "a" * 63, [], {}]
)
def test_registry_hash_grammar(hash_value: Any) -> None:
    receipt = _receipt()
    receipt["payload"]["registry_hash"] = hash_value
    with pytest.raises(ReceiptError):
        normalize_evidence_receipt(receipt)


@pytest.mark.parametrize(
    "field,value",
    [
        ("crit", ["canonicalization"]),
        ("crit", [SECRET_EGRESS_PAYLOAD_KIND]),
        (
            "crit",
            [
                "canonicalization",
                SECRET_EGRESS_PAYLOAD_KIND,
                SECRET_EGRESS_PAYLOAD_KIND,
            ],
        ),
        ("crit", ["canonicalization", SECRET_EGRESS_PAYLOAD_KIND, "source_spans"]),
        ("crit", ["canonicalization", SECRET_EGRESS_PAYLOAD_KIND, "unknown"]),
        ("policy_hash", None),
        ("policy_hash", ""),
        ("policy_hash", "sha256:" + "A" * 64),
        ("canonicalization", None),
    ],
)
def test_new_kind_requires_envelope_bindings(field: str, value: Any) -> None:
    receipt = _receipt()
    receipt[field] = value
    with pytest.raises(ReceiptError):
        normalize_evidence_receipt(receipt)


def test_new_crit_cannot_be_attached_to_legacy_kind() -> None:
    receipt = _receipt()
    receipt["payload_kind"] = "proxy_decision"
    with pytest.raises(ReceiptError, match="crit"):
        normalize_evidence_receipt(receipt)


def test_new_kind_requires_receipt_signing_key_purpose() -> None:
    receipt = _receipt()
    receipt["signature"]["key_purpose"] = "policy-signing"
    with pytest.raises(ReceiptError, match="key_purpose"):
        normalize_evidence_receipt(receipt)


def test_payload_tampering_invalidates_signature() -> None:
    receipt = _receipt()
    receipt["payload"]["decision"]["destination_ref"] = "other.vendor.example"
    with pytest.raises(ReceiptError, match="signature verification failed"):
        verify_evidence_receipt(receipt, PUBLIC_KEY)


def test_intent_and_outcome_chain_allows_enforcement_failure() -> None:
    intent = _receipt()
    outcome = copy.deepcopy(intent)
    outcome["event_id"] = "outcome-event"
    outcome["chain_seq"] = 1
    outcome["chain_prev_hash"] = receipt_hash(intent)
    outcome["payload"]["decision"].update(
        phase="outcome", outcome={"release": "complete", "byte_form": "original"}
    )
    _sign(outcome)
    result = verify_evidence_chain([intent, outcome], PUBLIC_KEY)
    assert result["valid"] is True, result


@pytest.mark.parametrize("literal", ["1.0", "1e0", "1E+0"])
def test_decision_version_rejects_noninteger_lexical_forms(
    tmp_path: Path, literal: str
) -> None:
    raw = json.dumps(_receipt(), separators=(",", ":")).replace(
        '"version":1', '"version":' + literal
    )
    path = tmp_path / "noninteger.json"
    path.write_text(raw)
    result = verify_receipt_file(path, PUBLIC_KEY)
    assert result["valid"] is False, result
    assert "decision version" in result["error"]


@pytest.mark.parametrize("length", [16384, 16385])
def test_nested_source_byte_limit_single_and_chain(tmp_path: Path, length: int) -> None:
    receipt = _receipt()
    decision_text = json.dumps(receipt["payload"]["decision"], separators=(",", ":"))
    padded = "{" + " " * (length - len(decision_text)) + decision_text[1:]
    raw = json.dumps(receipt, separators=(",", ":")).replace(decision_text, padded)
    path = tmp_path / "large.json"
    path.write_text(raw)
    result = verify_receipt_file(path, PUBLIC_KEY)
    assert result["valid"] is (length == 16384), result
    chain = tmp_path / "large.jsonl"
    chain.write_text('{"type":"evidence_receipt","detail":' + raw + "}\n")
    if length == 16384:
        receipts = load_evidence_chain(chain)
        assert verify_evidence_chain(receipts, PUBLIC_KEY)["valid"] is True
    else:
        with pytest.raises(ReceiptError, match="decision size"):
            load_evidence_chain(chain)


@pytest.mark.parametrize(
    "mutation", ["duplicate_decision", "duplicate_payload", "trailing"]
)
def test_strict_json_survives_new_payload_dispatch(
    tmp_path: Path, mutation: str
) -> None:
    raw = json.dumps(_receipt(), separators=(",", ":"))
    if mutation == "duplicate_decision":
        raw = raw.replace('"version":1', '"version":1,"version":1')
    elif mutation == "duplicate_payload":
        raw = raw.replace(
            '"registry_hash":', '"registry_hash":"duplicate","registry_hash":'
        )
    else:
        raw += "{}"
    path = tmp_path / "invalid.json"
    path.write_text(raw)
    with pytest.raises(ReceiptError):
        load_receipt(path)


def test_jcs_verification_accepts_reformatted_key_reordered_input(
    tmp_path: Path,
) -> None:
    receipt = _receipt()
    path = tmp_path / "reformatted.json"
    path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    result = verify_receipt_file(path, PUBLIC_KEY)
    assert result["valid"] is True, result


@pytest.mark.parametrize(
    "field", ["plane", "transport", "destination_kind", "finding_disposition", "phase"]
)
def test_unknown_enum_values_fail_closed(field: str) -> None:
    decision = _decision()
    decision[field] = "unknown"
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize(
    "fallback",
    [
        None,
        [],
        {},
        {
            "reason": "opaque_arguments",
            "policy_ref": "fallback",
            "policy_origin": "builtin",
            "extra": "x",
        },
    ],
)
def test_fallback_optional_field_must_be_strict_when_present(fallback: Any) -> None:
    decision = _decision()
    decision["rewrite_fallback"] = fallback
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize("wrapper", ["action_receipt", "evidence_receipt"])
def test_recorder_and_receipt_kinds_must_agree(tmp_path: Path, wrapper: str) -> None:
    receipt = _receipt()
    if wrapper == "evidence_receipt":
        receipt = json.loads(
            (ROOT / "sdk/conformance/testdata/valid-single.json").read_text()
        )
    path = tmp_path / "kind-mismatch.jsonl"
    path.write_text(json.dumps({"type": wrapper, "detail": receipt}) + "\n")
    with pytest.raises(ReceiptError, match="recorder and receipt kind disagree"):
        load_evidence_chain(path)


@pytest.mark.parametrize("wrapper", ["action_receipt", "evidence_receipt"])
def test_raw_decision_bound_checked_before_recorder_split(
    tmp_path: Path, wrapper: str
) -> None:
    receipt = _receipt()
    decision = json.dumps(receipt["payload"]["decision"])
    raw = json.dumps({"type": wrapper, "detail": receipt})
    raw = raw.replace(decision, "{" + " " * 16384 + decision[1:])
    path = tmp_path / "bounded-recorder.jsonl"
    path.write_text(raw + "\n")
    with pytest.raises(ReceiptError, match="decision size"):
        load_evidence_chain(path)


@pytest.mark.parametrize("transport", ["mcp_stdio", "mcp_http", "mcp_websocket"])
def test_network_destination_rejects_local_and_retired_transports(
    transport: str,
) -> None:
    decision = _decision()
    decision["transport"] = transport
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize(
    "field",
    [
        "record_type",
        "receipt_version",
        "payload_kind",
        "canonicalization",
        "crit",
        "event_id",
        "timestamp",
        "signature",
        "chain_seq",
        "chain_prev_hash",
        "policy_hash",
        "payload",
    ],
)
@pytest.mark.parametrize("mutation", ["missing", "null", "case"])
def test_newkind_envelope_fields_are_exact_and_required(
    field: str, mutation: str
) -> None:
    from pipelock_aarp_verify.secret_egress import validate_envelope

    receipt = _receipt()
    if mutation == "missing":
        del receipt[field]
    elif mutation == "case":
        receipt[field.upper()] = receipt.pop(field)
    else:
        receipt[field] = None
    with pytest.raises(SecretEgressError):
        validate_envelope(receipt)


@pytest.mark.parametrize(
    "field",
    ["principal", "actor", "active_manifest_hash", "contract_hash", "selector_id"],
)
@pytest.mark.parametrize("value", [None, "", [], {}, 1, False])
def test_newkind_optional_strings_cannot_be_empty_or_wrong_type(
    field: str, value: Any
) -> None:
    receipt = _receipt()
    receipt[field] = value
    with pytest.raises(ReceiptError):
        normalize_evidence_receipt(receipt)


@pytest.mark.parametrize("value", [None, [], [""], [None], [1], [False], {}, "actor"])
def test_newkind_delegation_chain_is_nonempty_strings(value: Any) -> None:
    receipt = _receipt()
    receipt["delegation_chain"] = value
    with pytest.raises(ReceiptError):
        normalize_evidence_receipt(receipt)


@pytest.mark.parametrize(
    "field,minimum", [("chain_seq", 0), ("contract_generation", 1)]
)
@pytest.mark.parametrize(
    "value", [None, True, False, -1, 1.5, 1.0, "1", 9007199254740992]
)
def test_newkind_envelope_integer_types(field: str, minimum: int, value: Any) -> None:
    receipt = _receipt()
    receipt[field] = value
    with pytest.raises(ReceiptError):
        normalize_evidence_receipt(receipt)
    receipt[field] = minimum
    normalize_evidence_receipt(receipt)
    receipt[field] = 9007199254740991
    normalize_evidence_receipt(receipt)


@pytest.mark.parametrize(
    "field,literal",
    [
        ("receipt_version", "2.0"),
        ("receipt_version", "2e0"),
        ("chain_seq", "-0"),
        ("chain_seq", "0.0"),
        ("chain_seq", "0e0"),
        ("contract_generation", "1.0"),
        ("contract_generation", "1e0"),
    ],
)
def test_newkind_raw_envelope_integer_spellings(
    tmp_path: Path, field: str, literal: str
) -> None:
    receipt = _receipt()
    receipt["contract_generation"] = 1
    _sign(receipt)
    raw = json.dumps(receipt, separators=(",", ":"))
    raw = raw.replace(f'"{field}":{receipt[field]}', f'"{field}":{literal}')
    path = tmp_path / "envelope-number.json"
    path.write_text(raw)
    assert verify_receipt_file(path, PUBLIC_KEY)["valid"] is False
    path.write_text('{"type":"evidence_receipt","detail":' + raw + "}\n")
    with pytest.raises(ReceiptError):
        load_evidence_chain(path)


def test_newkind_optional_profile_fields_preserve_valid_signatures(
    tmp_path: Path,
) -> None:
    receipt = _receipt()
    receipt.update(
        principal="fixture.principal",
        actor="fixture.actor",
        delegation_chain=["fixture.delegation"],
        active_manifest_hash="fixture.manifest",
        contract_hash="fixture.contract",
        selector_id="fixture.selector",
        contract_generation=1,
    )
    _sign(receipt)
    result = verify_receipt_file(_write(tmp_path, receipt), PUBLIC_KEY)
    assert result["valid"] is True, result
    assert result["transport"] == "forward"
    receipt["contract_generation"] = 0
    with pytest.raises(ReceiptError):
        normalize_evidence_receipt(receipt)


@pytest.mark.parametrize(
    "timestamp,valid",
    [
        ("2026-09-30T12:34:56Z", True),
        ("2026-09-30T12:34:56.123456789Z", True),
        ("2026-09-30T12:34:56.000000001Z", True),
        ("0000-02-29T00:00:00Z", True),
        ("0001-01-01T00:00:00.1Z", True),
        ("9999-12-31T23:59:59Z", True),
        ("0001-01-01T00:00:00Z", False),
        ("2026-02-29T12:34:56Z", False),
        ("2026-09-30T24:00:00Z", False),
        ("2026-09-30T12:60:00Z", False),
        ("2026-09-30T12:34:60Z", False),
        ("2026-09-30T12:34:56.0Z", False),
        ("2026-09-30T12:34:56.10Z", False),
        ("2026-09-30T12:34:56.1234567891Z", False),
        ("2026-09-30T12:34:56+00:00", False),
        ("2026-09-30T12:34:56-00:00", False),
        ("2026-09-30T12:34:56+01:00", False),
        ("2026-09-30T1:34:56Z", False),
        ("2026-09-30T12:34:56,1Z", False),
        ("2026-09-30T12:34:56Z\n", False),
        ("2026-00-30T12:34:56Z", False),
        ("2026-09-00T12:34:56Z", False),
    ],
)
def test_newkind_canonical_utc_timestamp(timestamp: str, valid: bool) -> None:
    receipt = _receipt()
    receipt["timestamp"] = timestamp
    if valid:
        normalize_evidence_receipt(receipt)
    else:
        with pytest.raises(ReceiptError):
            normalize_evidence_receipt(receipt)


def test_newkind_timestamp_requires_unescaped_ascii_token(tmp_path: Path) -> None:
    receipt = _receipt()
    raw = json.dumps(receipt, separators=(",", ":"))
    escaped_timestamp = '"\\u0032' + receipt["timestamp"][1:] + '"'
    escaped = raw.replace(json.dumps(receipt["timestamp"]), escaped_timestamp)
    assert escaped != raw
    assert json.loads(escaped)["timestamp"] == receipt["timestamp"]
    path = tmp_path / "timestamp.json"
    path.write_text(raw)
    assert verify_receipt_file(path, PUBLIC_KEY)["valid"] is True
    path.write_text(escaped)
    result = verify_receipt_file(path, PUBLIC_KEY)
    assert result["valid"] is False
    assert "raw timestamp spelling" in result["error"]
    recorder = tmp_path / "timestamp.jsonl"
    recorder.write_text('{"type":"evidence_receipt","detail":' + raw + "}\n")
    assert len(load_evidence_chain(recorder)) == 1
    recorder.write_text('{"type":"evidence_receipt","detail":' + escaped + "}\n")
    with pytest.raises(ReceiptError, match="raw timestamp spelling"):
        load_evidence_chain(recorder)


@pytest.mark.parametrize(
    "mutation",
    [
        "uppercase_hex",
        "uppercase_prefix",
        "leading_space",
        "trailing_space",
        "embedded_space",
        "trailing_newline",
        "trailing_tab",
        "unicode_hex",
        "short",
        "long",
    ],
)
def test_newkind_signature_encoding_is_exact_lowercase(
    tmp_path: Path, mutation: str
) -> None:
    receipt = _receipt()
    proof = receipt["signature"]["signature"]
    variants = {
        "uppercase_hex": "ed25519:" + proof[8:].upper(),
        "uppercase_prefix": "ED25519:" + proof[8:],
        "leading_space": " " + proof,
        "trailing_space": proof + " ",
        "embedded_space": proof[:10] + " " + proof[10:],
        "trailing_newline": proof + "\n",
        "trailing_tab": proof + "\t",
        "unicode_hex": "ed25519:ａ" + proof[9:],
        "short": proof[:-1],
        "long": proof + "a",
    }
    receipt["signature"]["signature"] = variants[mutation]
    with pytest.raises(ReceiptError, match="lowercase signature encoding"):
        normalize_evidence_receipt(receipt)
    report = verify_receipt_file(_write(tmp_path, receipt), PUBLIC_KEY)
    assert report["valid"] is False
    assert "lowercase signature encoding" in report["error"]
    recorder = tmp_path / "signature.jsonl"
    recorder.write_text(
        json.dumps({"type": "evidence_receipt", "detail": receipt}) + "\n"
    )
    with pytest.raises(ReceiptError, match="lowercase signature encoding"):
        load_evidence_chain(recorder)


def _redacted_decision() -> dict[str, Any]:
    decision = _decision()
    del decision["destination_ref"]
    decision["destination_redaction"] = {"reason": "classified_sensitive"}
    return decision


@pytest.mark.parametrize(
    "transport,boundary",
    [
        ("fetch", "upstream_request"),
        ("forward", "upstream_request"),
        ("connect", "tunnel_admission"),
        ("intercept", "upstream_request"),
        ("reverse", "upstream_request"),
        ("websocket", "upstream_frame"),
        ("mcp_stdio", "tool_dispatch"),
        ("mcp_http_upstream", "tool_dispatch"),
        ("mcp_http_listener", "tool_dispatch"),
        ("mcp_ws", "tool_dispatch"),
    ],
)
def test_redacted_destination_preserves_carrier_kind_matrix(
    transport: str, boundary: str
) -> None:
    decision = _redacted_decision()
    decision.update(
        transport=transport,
        boundary=boundary,
        destination_kind="local_process" if transport == "mcp_stdio" else "network",
    )
    validate_decision(decision)
    assert "destination_ref" not in decision
    decision["destination_kind"] = (
        "network" if transport == "mcp_stdio" else "local_process"
    )
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize(
    "redaction",
    [
        None,
        {},
        [],
        "classified_sensitive",
        1,
        False,
        {"reason": None},
        {"reason": ""},
        {"reason": "unknown"},
        {"reason": []},
        {"reason": "Classified_sensitive"},
        {"Reason": "classified_sensitive"},
        {"reason": "classified_sensitive", "extra": "fixture"},
    ],
)
def test_destination_redaction_is_strict_sum_variant(redaction: Any) -> None:
    decision = _redacted_decision()
    decision["destination_redaction"] = redaction
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize("reference", [None, "", "api.vendor.example"])
def test_destination_cannot_have_both_variants(reference: Any) -> None:
    decision = _redacted_decision()
    decision["destination_ref"] = reference
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


def test_destination_requires_one_exact_variant() -> None:
    decision = _redacted_decision()
    del decision["destination_redaction"]
    with pytest.raises(SecretEgressError):
        validate_decision(decision)
    decision["Destination_redaction"] = {"reason": "classified_sensitive"}
    with pytest.raises(SecretEgressError):
        validate_decision(decision)
    decision = _decision()
    decision["destination_ref"] = ""
    with pytest.raises(SecretEgressError):
        validate_decision(decision)


@pytest.mark.parametrize(
    "kind,transport", [("network", "forward"), ("local_process", "mcp_stdio")]
)
def test_signed_redacted_destination_without_placeholder(
    tmp_path: Path, kind: str, transport: str
) -> None:
    receipt = _receipt()
    decision = _redacted_decision()
    decision.update(destination_kind=kind, transport=transport)
    receipt["payload"]["decision"] = decision
    _sign(receipt)
    report = verify_receipt_file(_write(tmp_path, receipt), PUBLIC_KEY)
    assert report["valid"] is True, report
    assert report["transport"] == transport
    assert "destination_ref" not in receipt["payload"]["decision"]


def test_new_signature_profile_does_not_change_existing_v2_kind() -> None:
    receipt = json.loads(
        (
            ROOT
            / "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json"
        ).read_text()
    )
    _sign(receipt)
    proof = receipt["signature"]["signature"]
    receipt["signature"]["signature"] = "ed25519:" + proof[8:].upper()
    verify_evidence_receipt(receipt, PUBLIC_KEY)


def test_frozen_model_fixture_shapes_and_duplicate_rejection() -> None:
    directory = ROOT / "internal/egressevidence/testdata/decision-v1"
    manifest = json.loads((directory / "manifest.json").read_text())
    for fixture in manifest["fixtures"]:
        raw = (directory / fixture["file"]).read_text()
        try:
            parse_json_strict(raw)
            validate_decision(json.loads(raw))
        except (SecretEgressError, StrictParseError) as exc:
            assert not fixture["valid"], (fixture["id"], str(exc))
        else:
            assert fixture["valid"], fixture["id"]
