# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pipelock_aarp_verify.cli import main
from pipelock_aarp_verify.receipt import (
    ReceiptError,
    _canonicalize_action_record,
    compute_session_open_genesis,
    load_evidence_chain,
    receipt_hash,
    verify_evidence_chain,
    verify_receipt_file,
)

ROOT = Path(__file__).resolve().parents[4]
CORPUS = ROOT / "sdk/conformance/testdata/corpus"
CORPUS_KEY = json.loads((CORPUS / "test-key.json").read_text())["public_key_hex"]
TESTDATA = ROOT / "sdk/conformance/testdata"
TESTDATA_KEY_INFO = json.loads((TESTDATA / "test-key.json").read_text())
TESTDATA_KEY = TESTDATA_KEY_INFO["public_key_hex"]
TESTDATA_TRUSTED_KEYS = f"{TESTDATA_KEY_INFO['public_key_hex']},{TESTDATA_KEY_INFO['rotated_public_key_hex']}"
VALID_SPANNED_V2 = (
    ROOT
    / "internal/contract/testdata/golden/"
    / "valid_evidence_receipt_proxy_decision_with_spans.json"
)
VALID_PLAIN_V2 = (
    ROOT
    / "internal/contract/testdata/golden/"
    / "valid_evidence_receipt_proxy_decision.json"
)
V2_GOLDEN_PUBLIC_KEY = (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
V2_GOLDEN_POLICY_HASH = (
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)
V2_PRIVATE_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
TESTDATA_PRIVATE_SEED_HEX = TESTDATA_KEY_INFO["seed_hex"]


def test_valid_spanned_v2_receipt_verifies() -> None:
    report = verify_receipt_file(VALID_SPANNED_V2, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is True, report.get("error")
    assert report["action_id"] == "01F8MECHZX3TBDSZ7XRADM79ZS"
    assert report["verdict"] == "block"
    assert report["transport"] == "forward"
    assert report["signer_key"] == V2_GOLDEN_PUBLIC_KEY
    assert report["policy_hash"] == V2_GOLDEN_POLICY_HASH


def test_valid_plain_v2_receipt_verifies() -> None:
    report = verify_receipt_file(VALID_PLAIN_V2, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is True, report.get("error")
    assert report["policy_hash"] == V2_GOLDEN_POLICY_HASH


def test_valid_v1_run_nonce_receipt_verifies() -> None:
    report = verify_receipt_file(CORPUS / "golden/11-run-nonce-bound.json", CORPUS_KEY)
    assert report["valid"] is True, report.get("error")
    assert report["action_id"] == "conformance-00010"
    assert report["signer_key"] == CORPUS_KEY


def test_tampered_v1_run_nonce_receipt_rejects() -> None:
    report = verify_receipt_file(
        CORPUS / "malicious/m15-run-nonce-tampered.json", CORPUS_KEY
    )
    assert report["valid"] is False
    assert "signature verification failed" in report["error"]


def test_tampered_v1_receipt_rejects_even_when_unpinned_allowed() -> None:
    report = verify_receipt_file(
        CORPUS / "malicious/m15-run-nonce-tampered.json",
        "",
        allow_unpinned=True,
    )
    assert report["valid"] is False
    assert "signature verification failed" in report["error"]


def test_v1_receipt_with_unsigned_top_level_field_rejects(tmp_path: Path) -> None:
    receipt = json.loads((CORPUS / "golden/11-run-nonce-bound.json").read_text())
    receipt["unsigned_sidecar"] = "not-signed"
    path = tmp_path / "unsigned-sidecar.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, CORPUS_KEY)
    assert report["valid"] is False
    assert "receipt: unknown field unsigned_sidecar" in report["error"]


def test_v1_receipt_with_unsigned_action_field_rejects(tmp_path: Path) -> None:
    receipt = json.loads((CORPUS / "golden/11-run-nonce-bound.json").read_text())
    receipt["action_record"]["unsigned_sidecar"] = "not-signed"
    path = tmp_path / "unsigned-action-field.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, CORPUS_KEY)
    assert report["valid"] is False
    assert "action_record: unknown field unsigned_sidecar" in report["error"]


def test_v1_receipt_with_malformed_run_nonce_rejects_before_signature(
    tmp_path: Path,
) -> None:
    receipt = json.loads((CORPUS / "golden/11-run-nonce-bound.json").read_text())
    receipt["action_record"]["run_nonce"] = "0123456789ABCDEF0123456789ABCDEF"
    path = tmp_path / "malformed-run-nonce.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, CORPUS_KEY)
    assert report["valid"] is False
    assert "run_nonce must be 32 lowercase hex chars" in report["error"]


def test_legacy_v1_receipt_without_run_nonce_still_verifies() -> None:
    report = verify_receipt_file(CORPUS / "golden/01-allow-clean-get.json", CORPUS_KEY)
    assert report["valid"] is True, report.get("error")


def test_missing_v2_policy_hash_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_PLAIN_V2.read_text())
    del receipt["policy_hash"]
    path = tmp_path / "missing-policy-hash.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "policy_hash" in report["error"]


def test_reserved_defer_v2_payload_kind_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_PLAIN_V2.read_text())
    receipt["payload_kind"] = "defer_opened"
    path = tmp_path / "reserved-defer.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "known but not implemented" in report["error"]


def test_tampered_spanned_v2_receipt_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["payload"]["source_spans"][0]["rule_id"] = "aws_access_key_tampered"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "signature verification failed" in report["error"]


def test_unknown_spanned_v2_field_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["payload"]["source_spans"][0]["raw_match"] = "lowentropy"
    path = tmp_path / "unknown.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "unknown field raw_match" in report["error"]


def test_empty_dlp_normalized_suffix_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["payload"]["source_spans"][0]["normalized_view"] = "dlp_normalized:"
    path = tmp_path / "empty-view.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "normalized_view is invalid" in report["error"]


def test_optional_span_metadata_must_be_string(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["payload"]["source_spans"][0]["redacted_sample"] = 42
    path = tmp_path / "bad-optional-span-field.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "redacted_sample must be a string" in report["error"]


def test_unsupported_canonicalization_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["canonicalization"]["jcs_profile"] = "rfc8785"
    path = tmp_path / "bad-canonicalization.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "canonicalization.jcs_profile is invalid" in report["error"]


def test_missing_source_spans_crit_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["crit"] = ["canonicalization"]
    path = tmp_path / "missing-source-span-crit.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "crit must include source_spans" in report["error"]


def test_unknown_crit_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["crit"] = ["canonicalization", "source_spans", "future_extension"]
    path = tmp_path / "unknown-crit.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "crit has unknown field future_extension" in report["error"]


def test_source_spans_crit_on_plain_payload_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_PLAIN_V2.read_text())
    receipt["crit"] = ["canonicalization", "source_spans"]
    path = tmp_path / "plain-source-span-crit.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "crit source_spans is invalid for proxy_decision" in report["error"]


def test_spanned_v2_receipt_does_not_expose_oracle_key() -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    span = receipt["payload"]["source_spans"][0]
    assert span["match_hash_alg"] == "hmac-sha256"
    assert span["match_hash"].startswith("hmac-sha256:")
    assert "golden-span-mac-key" not in json.dumps(receipt)


def test_receipt_cli_json(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(
        ["receipt", str(VALID_SPANNED_V2), "--key", V2_GOLDEN_PUBLIC_KEY, "--json"]
    )
    captured = capsys.readouterr()
    assert code == 0
    body = json.loads(captured.out)
    assert body["valid"] is True


def test_receipt_cli_without_key_is_unpinned_nonzero(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(["receipt", str(VALID_SPANNED_V2), "--json"])
    captured = capsys.readouterr()
    assert code == 1
    body = json.loads(captured.out)
    assert body["valid"] is False
    assert body["unpinned"] is True


def test_receipt_cli_allow_unpinned_exits_zero(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(["receipt", str(VALID_SPANNED_V2), "--allow-unpinned", "--json"])
    captured = capsys.readouterr()
    assert code == 0
    body = json.loads(captured.out)
    assert body["valid"] is True
    assert body["unpinned"] is True


def test_v2_multi_receipt_chain_verifies() -> None:
    report = verify_evidence_chain(_build_v2_chain(2), V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is True, report.get("error")
    assert report["receipt_count"] == 2
    assert report["final_seq"] == 1


def test_v1_legacy_go_generated_chain_verifies() -> None:
    receipts = load_evidence_chain(TESTDATA / "valid-chain.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is True, report.get("error")
    assert report["receipt_count"] == 5
    assert report["final_seq"] == 4


def test_v1_g1_go_generated_chain_verifies() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-valid-chain.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is True, report.get("error")
    assert report["receipt_count"] == 5
    assert report["final_seq"] == 4


def test_v1_g1_restart_chain_verifies_with_prior_tail_fields() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-restart-chain.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is True, report.get("error")
    assert report["receipt_count"] == 5
    assert report["final_seq"] == 4
    restart_open = receipts[2]["action_record"]["session_control"]["open"]
    assert restart_open["prior_chain_seq"] == 1
    assert restart_open["prior_chain_head"] != ""


def test_v1_g1_restart_close_receipt_count_mismatch_rejects_valid_signature() -> None:
    receipts = json.loads(
        json.dumps(load_evidence_chain(TESTDATA / "g1-restart-chain.jsonl"))
    )
    receipts[4]["action_record"]["session_control"]["close"]["receipt_count"] = 3
    _sign_v1_action_receipt(receipts[4])

    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert "session_close receipt_count mismatch" in report["error"]


def test_v1_g1_genesis_vectors_match_go() -> None:
    vectors = json.loads((TESTDATA / "g1-genesis-vectors.json").read_text())
    assert len(vectors) >= 5
    for vector in vectors:
        assert compute_session_open_genesis(vector["open"]) == vector["expected"]


def test_v1_g1_broken_genesis_is_rejected() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-broken-genesis.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert report["broken_at_seq"] == 0
    assert "session_open genesis hash mismatch" in report["error"]


def test_v1_g1_legacy_session_open_on_genesis_is_rejected() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-legacy-open-genesis.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert report["broken_at_seq"] == 0
    assert "session_open on legacy genesis" in report["error"]


def test_v1_g1_inconsistent_heartbeat_fixture_is_rejected() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-inconsistent-heartbeat.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert report["broken_at_seq"] == 3
    assert "heartbeat chain_head mismatch" in report["error"]


def test_v1_g1_inconsistent_close_fixture_is_rejected() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-inconsistent-close.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert report["broken_at_seq"] == 4
    assert "session_close root_hash mismatch" in report["error"]


def test_v1_g1_ambiguous_session_control_fixture_is_rejected() -> None:
    for name in (
        "g1-ambiguous-session-control.jsonl",
        "g1-ambiguous-open-close.jsonl",
        "g1-ambiguous-heartbeat-close.jsonl",
    ):
        receipts = load_evidence_chain(TESTDATA / name)
        report = verify_evidence_chain(receipts, TESTDATA_KEY)
        assert report["valid"] is False, name
        assert "session_control must carry exactly one payload" in report["error"]


def test_v1_g1_rotated_close_count_valid_fixture_verifies() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-rotated-close-count-valid.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_TRUSTED_KEYS)
    assert report["valid"] is True, report.get("error")
    assert report["receipt_count"] == 6
    assert report["final_seq"] == 2


def test_v1_g1_rotated_close_count_invalid_fixture_is_rejected() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-rotated-close-count-invalid.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_TRUSTED_KEYS)
    assert report["valid"] is False
    assert "session_close receipt_count mismatch" in report["error"]


def test_v1_g1_plain_action_after_close_fixture_is_rejected() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-plain-after-close.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert "record observed after session_close" in report["error"]


def test_v1_g1_empty_run_nonce_after_close_fixture_verifies() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-empty-run-nonce-after-close.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is True, report.get("error")


def test_v1_g1_heartbeat_after_close_fixture_is_rejected() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-heartbeat-after-close.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert "record observed after session_close" in report["error"]


def test_v1_g1_close_without_open_fixture_is_rejected() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-close-without-open.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert "first receipt is not a matching session_open" in report["error"]


def test_v1_g1_new_session_after_close_fixture_verifies() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-new-session-after-close.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is True, report.get("error")


def test_v1_g1_reopen_closed_run_fixture_is_rejected() -> None:
    receipts = load_evidence_chain(TESTDATA / "g1-reopen-closed-run.jsonl")
    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert "duplicate session_open for run_nonce" in report["error"]


def test_v1_g1_signed_field_tampering_is_rejected() -> None:
    def tamper_open_posture_signer(receipts: list[dict[str, object]]) -> None:
        receipts[0]["action_record"]["session_control"]["open"][
            "posture_signer_key_id"
        ] = "posture-key-tampered"

    def tamper_decision_phase(receipts: list[dict[str, object]]) -> None:
        receipts[1]["action_record"]["decision_phase"] = "outcome"

    def tamper_heartbeat_beat(receipts: list[dict[str, object]]) -> None:
        receipts[3]["action_record"]["session_control"]["heartbeat"]["beat"] = 2

    def tamper_heartbeat_fsync(receipts: list[dict[str, object]]) -> None:
        receipts[3]["action_record"]["session_control"]["heartbeat"][
            "fsync_errors_gated"
        ] = 99

    def tamper_close_root_hash(receipts: list[dict[str, object]]) -> None:
        receipts[4]["action_record"]["session_control"]["close"]["root_hash"] = (
            "tampered-root"
        )

    def tamper_close_durability(receipts: list[dict[str, object]]) -> None:
        receipts[4]["action_record"]["session_control"]["close"][
            "durability_blocks"
        ] = 99

    cases = {
        "session_open_posture_signer_key_id": tamper_open_posture_signer,
        "decision_phase": tamper_decision_phase,
        "heartbeat_beat": tamper_heartbeat_beat,
        "heartbeat_fsync_errors_gated": tamper_heartbeat_fsync,
        "close_root_hash": tamper_close_root_hash,
        "close_durability_blocks": tamper_close_durability,
    }
    for name, mutate in cases.items():
        receipts = json.loads(
            json.dumps(load_evidence_chain(TESTDATA / "g1-valid-chain.jsonl"))
        )
        mutate(receipts)
        report = verify_evidence_chain(receipts, TESTDATA_KEY)
        assert report["valid"] is False, name
        assert "signature" in report["error"], name


def test_v1_g1_missing_session_open_required_field_rejects() -> None:
    receipts = json.loads(
        json.dumps(load_evidence_chain(TESTDATA / "g1-valid-chain.jsonl"))
    )
    del receipts[0]["action_record"]["session_control"]["open"]["open_nonce"]

    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert "session_control.open.open_nonce is required" in report["error"]


def test_v1_g1_oversized_heartbeat_seconds_rejects_controlled() -> None:
    receipts = json.loads(
        json.dumps(load_evidence_chain(TESTDATA / "g1-valid-chain.jsonl"))
    )
    receipts[0]["action_record"]["session_control"]["open"]["heartbeat_seconds"] = 2**64
    _sign_v1_action_receipt(receipts[0])

    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert "session_control.open.heartbeat_seconds must be a uint64" in report["error"]


def test_v1_g1_restart_prior_tail_mismatch_rejects_valid_signature() -> None:
    receipts = json.loads(
        json.dumps(load_evidence_chain(TESTDATA / "g1-restart-chain.jsonl"))
    )
    receipts[2]["action_record"]["session_control"]["open"]["prior_chain_head"] = (
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    _sign_v1_action_receipt(receipts[2])

    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert "session_open prior_chain_head does not match chain tail" in report["error"]


def test_v1_g1_heartbeat_chain_head_mismatch_rejects_valid_signature() -> None:
    receipts = json.loads(
        json.dumps(load_evidence_chain(TESTDATA / "g1-valid-chain.jsonl"))
    )
    receipts[3]["action_record"]["session_control"]["heartbeat"]["chain_head"] = (
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    _sign_v1_action_receipt(receipts[3])

    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert "heartbeat chain_head mismatch" in report["error"]


def test_v1_g1_close_root_hash_mismatch_rejects_valid_signature() -> None:
    receipts = json.loads(
        json.dumps(load_evidence_chain(TESTDATA / "g1-valid-chain.jsonl"))
    )
    receipts[4]["action_record"]["session_control"]["close"]["root_hash"] = (
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    )
    _sign_v1_action_receipt(receipts[4])

    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert "session_close root_hash mismatch" in report["error"]


def test_v1_g1_session_control_missing_record_run_nonce_rejects_valid_signature() -> (
    None
):
    receipts = json.loads(
        json.dumps(load_evidence_chain(TESTDATA / "g1-valid-chain.jsonl"))
    )
    del receipts[3]["action_record"]["run_nonce"]
    _sign_v1_action_receipt(receipts[3])

    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert report["broken_at_seq"] == 3
    assert "session_control receipt missing run_nonce" in report["error"]


def test_v1_g1_non_terminal_close_rejects_valid_signature() -> None:
    receipts = json.loads(
        json.dumps(load_evidence_chain(TESTDATA / "g1-valid-chain.jsonl"))
    )

    heartbeat = receipts[3]["action_record"]["session_control"]["heartbeat"]
    close = receipts[4]["action_record"]["session_control"]["close"]
    close["root_hash"] = receipts[3]["action_record"]["chain_prev_hash"]
    close["final_seq"] = 3
    close["receipt_count"] = 4
    receipts[3]["action_record"]["session_control"] = {
        "kind": "session_close",
        "close": close,
    }
    _sign_v1_action_receipt(receipts[3])

    receipts[4]["action_record"]["chain_prev_hash"] = receipt_hash(receipts[3])
    heartbeat["chain_head"] = receipts[4]["action_record"]["chain_prev_hash"]
    heartbeat["chain_seq_head"] = 3
    receipts[4]["action_record"]["session_control"] = {
        "kind": "heartbeat",
        "heartbeat": heartbeat,
    }
    _sign_v1_action_receipt(receipts[4])

    report = verify_evidence_chain(receipts, TESTDATA_KEY)
    assert report["valid"] is False
    assert "record observed after session_close" in report["error"]


def test_mixed_action_and_evidence_chain_rejects_controlled(tmp_path: Path) -> None:
    action_line = (TESTDATA / "g1-valid-chain.jsonl").read_text().splitlines()[0]
    evidence = json.loads(VALID_PLAIN_V2.read_text())
    mixed = tmp_path / "mixed.jsonl"
    mixed.write_text(
        action_line
        + "\n"
        + json.dumps({"type": "evidence_receipt", "detail": evidence})
        + "\n"
    )

    try:
        load_evidence_chain(mixed)
    except ReceiptError as exc:
        assert "mixed action/evidence receipt chains are not supported" in str(exc)
    else:
        raise AssertionError("mixed chain unexpectedly loaded")


def test_v2_tampered_chain_fails_closed() -> None:
    receipts = _build_v2_chain(2)
    receipts[1]["chain_prev_hash"] = "sha256:0"
    report = verify_evidence_chain(receipts, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "signature" in report["error"] or "chain_prev_hash" in report["error"]


def test_v2_truncated_middle_receipt_fails_closed() -> None:
    receipts = _build_v2_chain(3)
    del receipts[1]
    report = verify_evidence_chain(receipts, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "signature" in report["error"] or "seq gap" in report["error"]


def _build_v2_chain(count: int) -> list[dict[str, object]]:
    base = json.loads(VALID_PLAIN_V2.read_text())
    receipts: list[dict[str, object]] = []
    prev_hash = "genesis"
    for i in range(count):
        receipt = json.loads(json.dumps(base))
        receipt["event_id"] = f"01F8MECHZX3TBDSZ7XRADM79V{i}"
        receipt["chain_seq"] = i
        receipt["chain_prev_hash"] = prev_hash
        _sign_v2_receipt(receipt)
        receipts.append(receipt)
        prev_hash = receipt_hash(receipt)
    return receipts


def _sign_v2_receipt(receipt: dict[str, object]) -> None:
    from pipelock_aarp_verify.canonical import canonicalize

    signature = receipt["signature"]
    assert isinstance(signature, dict)
    receipt["signature"] = {
        "signer_key_id": "",
        "key_purpose": "",
        "algorithm": "",
        "signature": "",
    }
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V2_PRIVATE_SEED_HEX))
    sig = key.sign(canonicalize(receipt))
    receipt["signature"] = {
        "signer_key_id": signature.get("signer_key_id", "receipt-signing-test"),
        "key_purpose": "receipt-signing",
        "algorithm": "ed25519",
        "signature": f"ed25519:{sig.hex()}",
    }


def _sign_v1_action_receipt(receipt: dict[str, object]) -> None:
    action_record = receipt["action_record"]
    assert isinstance(action_record, dict)
    digest = hashlib.sha256(_canonicalize_action_record(action_record)).digest()
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(TESTDATA_PRIVATE_SEED_HEX))
    sig = key.sign(digest)
    receipt["signature"] = f"ed25519:{sig.hex()}"
    receipt["signer_key"] = TESTDATA_KEY
