# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""EvidenceReceipt v2 verifier used by the cross-language conformance gate."""

from __future__ import annotations

import binascii
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonicalize
from .number import (
    StrictParseError,
    UnsafeNumberError,
    enforce_cross_language_number_range,
    parse_json_strict,
)

V2_RECORD_TYPE = "evidence_receipt_v2"
SIGNATURE_PREFIX = "ed25519:"
V2_SIGNATURE_ALGORITHM = "ed25519"
V2_JCS_PROFILE = "pipelock-jcs-rfc8785-nfc-v1"
V2_JCS_VERSION = "rfc8785"
V2_HASH_ALG = "sha256"
V2_REDACTION_RULESET_ID = "pipelock-transform-v1"
V2_REDACTION_RULESET_VERSION = "1"
V2_REDACTION_RULESET_HASH = (
    "sha256:541896788b42651a202448894583a847db9d1aa081c33a7e1f0512303d72527e"
)
CRIT_CANONICALIZATION = "canonicalization"
CRIT_SOURCE_SPANS = "source_spans"
GENESIS_HASH = "genesis"
GENESIS_SESSION_OPEN_PREFIX = "g1:"
SESSION_OPEN_GENESIS_LABEL = "pipelock.receipt.session_open.v1"
EVIDENCE_ENTRY_TYPE = "evidence_receipt"
ACTION_ENTRY_TYPE = "action_receipt"
MAX_UINT64 = (1 << 64) - 1
UNPINNED_RECEIPT_BANNER = (
    "UNPINNED — signature is self-consistent but the signer was NOT checked "
    "against a trusted key"
)

_PAYLOAD_KINDS = {
    "proxy_decision",
    "proxy_decision_with_spans",
}
_POLICY_HASH_PAYLOAD_KINDS = {
    "proxy_decision",
    "proxy_decision_with_spans",
}
_RESERVED_PAYLOAD_KINDS = {
    "defer_opened",
    "defer_resolved",
}

_ENVELOPE_FIELDS = {
    "record_type",
    "receipt_version",
    "payload_kind",
    "canonicalization",
    "crit",
    "event_id",
    "timestamp",
    "principal",
    "actor",
    "delegation_chain",
    "signature",
    "chain_seq",
    "chain_prev_hash",
    "active_manifest_hash",
    "contract_hash",
    "policy_hash",
    "selector_id",
    "contract_generation",
    "payload",
}

_CANONICALIZATION_FIELDS = {
    "jcs_profile",
    "jcs_version",
    "hash_alg",
    "sig_alg",
    "redaction_ruleset_id",
    "redaction_ruleset_version",
    "redaction_ruleset_hash",
}

_SIGNATURE_FIELDS = {"signer_key_id", "key_purpose", "algorithm", "signature"}

_PROXY_DECISION_FIELDS = {
    "action_type",
    "target",
    "verdict",
    "live_verdict",
    "transport",
    "policy_sources",
    "winning_source",
    "rule_id",
}

_SOURCE_SPAN_FIELDS = {
    "source_id",
    "source_kind",
    "normalized_view",
    "pipelock_binary_digest",
    "rules_bundle_digest",
    "transform_profile",
    "policy_hash",
    "rule_id",
    "bundle",
    "bundle_version",
    "char_offset",
    "char_length",
    "match_hash",
    "match_hash_alg",
    "match_class",
    "redacted_sample",
}

_SOURCE_KINDS = {
    "http_request_url",
    "http_response",
    "mcp_tool_result",
    "mcp_tool_args",
}

_NORMALIZED_VIEWS = {
    "sanitized_target",
    "for_matching",
    "for_matching:invisible_spaced",
    "leetspeak:for_matching",
    "vowel_fold:for_matching",
    "for_matching:base64_decoded",
    "for_matching:hex_decoded",
    "dlp_normalized",
}

_ACTION_RECORD_FIELDS: tuple[tuple[str, bool, str | None], ...] = (
    ("version", False, None),
    ("action_id", False, None),
    ("parent_action_id", True, None),
    ("action_type", False, None),
    ("timestamp", False, None),
    ("principal", False, None),
    ("actor", False, None),
    ("delegation_chain", False, None),
    ("target", False, None),
    ("intent", True, None),
    ("data_classes_in", True, None),
    ("data_classes_out", True, None),
    ("side_effect_class", False, None),
    ("reversibility", False, None),
    ("policy_hash", False, None),
    ("verdict", False, None),
    ("decision_phase", True, None),
    ("defer_id", True, None),
    ("resolution_policy", True, None),
    ("resolution_source", True, None),
    ("session_id", True, None),
    ("session_id_original", True, None),
    ("session_taint_level", True, None),
    ("session_contaminated", True, None),
    ("recent_taint_sources", True, "taint_source"),
    ("session_task_id", True, None),
    ("session_task_label", True, None),
    ("authority_kind", True, None),
    ("taint_decision", True, None),
    ("taint_decision_reason", True, None),
    ("task_override_applied", True, None),
    ("contract_winning_source", True, None),
    ("contract_live_verdict", True, None),
    ("contract_policy_sources", True, None),
    ("contract_rule_id", True, None),
    ("active_manifest_hash", True, None),
    ("contract_hash", True, None),
    ("contract_selector_id", True, None),
    ("contract_generation", True, None),
    ("transport", False, None),
    ("method", True, None),
    ("layer", True, None),
    ("pattern", True, None),
    ("severity", True, None),
    ("redaction", True, "redaction"),
    ("shield", True, "shield"),
    ("request_id", True, None),
    ("chain_prev_hash", False, None),
    ("chain_seq", False, None),
    ("run_nonce", True, None),
    ("key_transition", True, "key_transition"),
    ("session_control", True, "session_control"),
    ("venue", True, None),
    ("jurisdiction", True, None),
    ("rulebook_id", True, None),
    ("remedy_class", True, None),
    ("contestation_window", True, None),
    ("precedent_refs", True, None),
)

_RECEIPT_FIELDS: tuple[tuple[str, bool, str | None], ...] = (
    ("version", False, None),
    ("action_record", False, "action_record"),
    ("signature", False, None),
    ("signer_key", False, None),
)

_REDACTION_FIELDS: tuple[tuple[str, bool, str | None], ...] = (
    ("profile", True, None),
    ("provider", True, None),
    ("parser", True, None),
    ("total_redactions", True, None),
    ("by_class", True, None),
    ("cache_boundary_kept", True, None),
)

_SHIELD_FIELDS: tuple[tuple[str, bool, str | None], ...] = (
    ("pipeline", True, None),
    ("total_rewrites", True, None),
    ("extension_probes", True, None),
    ("tracking_beacons", True, None),
    ("agent_traps", True, None),
    ("fingerprint_shim_injected", True, None),
    ("svg_foreign_objects", True, None),
    ("svg_event_handlers", True, None),
    ("svg_external_references", True, None),
    ("svg_hidden_text", True, None),
    ("svg_animation_injections", True, None),
    ("body_bytes", True, None),
    ("scanned_bytes", True, None),
    ("partial", True, None),
    ("adaptive_signals_recorded", True, None),
    ("adaptive_signal_max_per_body", True, None),
)

_TAINT_SOURCE_FIELDS: tuple[tuple[str, bool, str | None], ...] = (
    ("url", False, None),
    ("kind", False, None),
    ("level", False, None),
    ("timestamp", False, None),
    ("receipt_id", True, None),
    ("match_reason", True, None),
)

_KEY_TRANSITION_FIELDS: tuple[tuple[str, bool, str | None], ...] = (
    ("prior_signer_key", False, None),
    ("prior_chain_seq", False, None),
    ("prior_chain_hash", False, None),
)

_SESSION_CONTROL_FIELDS: tuple[tuple[str, bool, str | None], ...] = (
    ("kind", False, None),
    ("open", True, "session_open"),
    ("heartbeat", True, "session_heartbeat"),
    ("close", True, "session_close"),
)

_SESSION_OPEN_FIELDS: tuple[tuple[str, bool, str | None], ...] = (
    ("run_nonce", False, None),
    ("open_nonce", False, None),
    ("recorder_session", False, None),
    ("policy_hash", False, None),
    ("signer_key_epoch", False, None),
    ("heartbeat_seconds", False, None),
    ("chain_open_seq", False, None),
    ("prior_chain_head", True, None),
    ("prior_chain_seq", True, None),
    ("genesis_hash", True, None),
    ("genesis_anchor_head", True, None),
    ("genesis_anchor_log", True, None),
    ("posture_capsule_sha256", True, None),
    ("posture_signer_key_id", True, None),
    ("containment_nonce", True, None),
    ("contained_uid", True, None),
)

_SESSION_HEARTBEAT_FIELDS: tuple[tuple[str, bool, str | None], ...] = (
    ("run_nonce", False, None),
    ("open_nonce", False, None),
    ("beat", False, None),
    ("chain_head", False, None),
    ("chain_seq_head", False, None),
    ("heartbeat_time", False, None),
    ("fsync_errors_gated", False, None),
    ("durability_blocks", False, None),
)

_SESSION_CLOSE_FIELDS: tuple[tuple[str, bool, str | None], ...] = (
    ("run_nonce", False, None),
    ("open_nonce", False, None),
    ("final_seq", False, None),
    ("root_hash", False, None),
    ("receipt_count", False, None),
    ("close_reason", False, None),
    ("fsync_errors_gated", False, None),
    ("durability_blocks", False, None),
)

_VALID_ACTION_TYPES = {
    "read",
    "derive",
    "write",
    "delegate",
    "authorize",
    "spend",
    "commit",
    "actuate",
    "unclassified",
}


class ReceiptError(Exception):
    """Receipt parsing, validation, or signature verification failed."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ReceiptError(f"duplicate object key: {key}")
        out[key] = value
    return out


# AF-37 receipt-chain mode: the known non-receipt operational entry types that
# extraction legitimately skips. Any entry whose type is outside the union of
# the receipt types and this set is REJECTED (fail-closed) rather than silently
# skipped, so a file mixing a valid chain with an unknown record type cannot be
# reported as a valid receipt subsequence.
_SKIPPABLE_ENTRY_TYPES = frozenset(
    {"checkpoint", "transcript_root", "decision", "capture", "capture_drop"}
)


def load_receipt(path: str | Path) -> dict[str, Any]:
    data = Path(path).read_text(encoding="utf-8")
    # Python is arbitrary-precision, so it neither rounds nor overflows on a
    # number outside the I-JSON safe range: it silently ACCEPTS what the Go,
    # Rust, and TypeScript verifiers now reject, which is the same
    # cross-language differential wearing a different mask. The AARP envelope
    # path already enforces this (envelope.py); the receipt path must match.
    #
    # Validate against the literal-preserving tree, then decode normally: the
    # safe-number check reads each number's SOURCE TEXT, which json.loads has
    # already discarded by converting to int, and callers of this function
    # expect plain ints rather than IJSONNumber.
    try:
        enforce_cross_language_number_range(parse_json_strict(data))
    except (StrictParseError, UnsafeNumberError) as exc:
        raise ReceiptError(str(exc)) from exc
    try:
        value = json.loads(data, object_pairs_hook=_reject_duplicate_pairs)
    except ReceiptError:
        raise
    except json.JSONDecodeError as exc:
        raise ReceiptError(f"malformed JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ReceiptError("receipt must be an object")
    return value


def verify_receipt_file(
    path: str | Path, key_hex: str = "", allow_unpinned: bool = False
) -> dict[str, Any]:
    clean = str(Path(path))
    report: dict[str, Any] = {"path": clean, "valid": False}
    try:
        receipt = load_receipt(clean)
        if receipt.get("record_type") != V2_RECORD_TYPE:
            action_record = receipt.get("action_record")
            if isinstance(action_record, dict):
                report["action_id"] = action_record.get("action_id")
                report["verdict"] = action_record.get("verdict")
                report["transport"] = action_record.get("transport")
                report["policy_hash"] = action_record.get("policy_hash")
                report["chain_seq"] = action_record.get("chain_seq")
            report["signer_key"] = receipt.get("signer_key")
            if key_hex:
                verify_action_receipt(receipt, key_hex)
            else:
                verify_action_receipt(receipt)
                report["unpinned"] = True
                report["error"] = UNPINNED_RECEIPT_BANNER
                report["valid"] = allow_unpinned
                return report
        else:
            report["action_id"] = receipt.get("event_id")
            payload = receipt.get("payload")
            if isinstance(payload, dict):
                report["verdict"] = payload.get("verdict")
                report["transport"] = payload.get("transport")
            report["signer_key"] = key_hex
            report["policy_hash"] = receipt.get("policy_hash")
            report["chain_seq"] = receipt.get("chain_seq")
            if key_hex:
                verify_evidence_receipt(receipt, key_hex)
            else:
                normalize_evidence_receipt(receipt)
                report["unpinned"] = True
                report["error"] = UNPINNED_RECEIPT_BANNER
                report["valid"] = allow_unpinned
                return report
        report["valid"] = True
    except Exception as exc:  # noqa: BLE001 - verifier report captures cause
        report["error"] = str(exc)
    return report


def verify_evidence_chain_file(
    path: str | Path, key_hex: str = "", allow_unpinned: bool = False
) -> dict[str, Any]:
    clean = str(Path(path))
    report: dict[str, Any] = {
        "path": clean,
        "valid": False,
        "receipt_count": 0,
        "final_seq": 0,
    }
    try:
        receipts = load_evidence_chain(clean)
        if not receipts:
            raise ReceiptError("empty chain")
        result = verify_evidence_chain(receipts, key_hex, allow_unpinned)
        report.update(result)
    except Exception as exc:  # noqa: BLE001 - verifier report captures cause
        report["error"] = str(exc)
    return report


def load_evidence_chain(path: str | Path) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    chain_type: str | None = None
    for index, line in enumerate(
        Path(path).read_text(encoding="utf-8").splitlines(), start=1
    ):
        raw = line.strip()
        if raw == "":
            continue
        try:
            enforce_cross_language_number_range(parse_json_strict(raw))
        except (StrictParseError, UnsafeNumberError) as exc:
            raise ReceiptError(f"line {index}: {exc}") from exc
        try:
            entry = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
        except ReceiptError:
            raise
        except json.JSONDecodeError as exc:
            raise ReceiptError(f"line {index}: malformed JSON: {exc}") from exc
        if not isinstance(entry, dict):
            raise ReceiptError(f"line {index}: recorder entry must be an object")
        entry_type = entry.get("type")
        if entry_type not in {ACTION_ENTRY_TYPE, EVIDENCE_ENTRY_TYPE}:
            # AF-37: skip only the known operational entry types; a type outside
            # the recorder taxonomy fails closed rather than being silently
            # dropped from a "valid receipt subsequence".
            if entry_type in _SKIPPABLE_ENTRY_TYPES:
                continue
            raise ReceiptError(
                f"line {index}: unexpected recorder entry type {entry_type!r}"
            )
        if chain_type is None:
            chain_type = entry_type
        elif entry_type != chain_type:
            raise ReceiptError("mixed action/evidence receipt chains are not supported")
        detail = entry.get("detail")
        if not isinstance(detail, dict):
            raise ReceiptError(f"line {index}: evidence entry has empty detail")
        receipts.append(detail)
    return receipts


def verify_evidence_chain(
    receipts: list[dict[str, Any]], key_hex: str = "", allow_unpinned: bool = False
) -> dict[str, Any]:
    if not receipts:
        raise ReceiptError("empty chain")
    if not key_hex and not allow_unpinned:
        return {
            "valid": False,
            "unpinned": True,
            "receipt_count": 0,
            "final_seq": 0,
            "error": UNPINNED_RECEIPT_BANNER,
            "broken_at_seq": 0,
        }
    if receipts[0].get("record_type") == V2_RECORD_TYPE:
        return _verify_v2_chain(receipts, key_hex, allow_unpinned)
    return _verify_action_chain(receipts, key_hex, allow_unpinned)


def _verify_v2_chain(
    receipts: list[dict[str, Any]], key_hex: str, allow_unpinned: bool
) -> dict[str, Any]:
    signer_id = _signature_signer_key_id(receipts[0])
    prev_hash = GENESIS_HASH
    for index, receipt in enumerate(receipts):
        seq = receipt.get("chain_seq", index)
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise ReceiptError(f"seq {index}: missing or invalid chain_seq")
        try:
            if key_hex:
                verify_evidence_receipt(receipt, key_hex)
            else:
                normalize_evidence_receipt(receipt)
        except ReceiptError as exc:
            return _broken_chain(seq, f"seq {seq}: signature: {exc}")
        if _signature_signer_key_id(receipt) != signer_id:
            return _broken_chain(
                seq, f"seq {seq}: signer_key_id breaks chain signer {signer_id}"
            )
        if seq != index:
            return _broken_chain(seq, f"seq gap: expected {index}, got {seq}")
        if receipt.get("chain_prev_hash") != prev_hash:
            return _broken_chain(seq, f"seq {seq}: chain_prev_hash mismatch")
        prev_hash = receipt_hash(receipt)
    return {
        "valid": True,
        "unpinned": (not key_hex and allow_unpinned) or None,
        "receipt_count": len(receipts),
        "final_seq": receipts[-1].get("chain_seq", 0),
        "root_hash": prev_hash,
    }


def _verify_action_chain(
    receipts: list[dict[str, Any]], key_hex: str, allow_unpinned: bool
) -> dict[str, Any]:
    trusted_keys = _parse_trusted_keys(key_hex)
    first_key = _require_string(receipts[0].get("signer_key"), "signer_key").lower()
    if trusted_keys and first_key not in trusted_keys:
        return _broken_chain(0, f"signer key {first_key} is not in the trusted set")
    state: dict[str, Any] = {
        "cur_key": first_key,
        "segment_start_index": 0,
        "segment_base_seq": 0,
        "segment_receipt_count": 0,
        "prev_hash": "",
        "prior_segment_seq": None,
        "active_run_nonce": None,
        "active_open_nonce": None,
        "opened_runs": set(),
        "closed_runs": set(),
    }
    for index, receipt in enumerate(receipts):
        action_record = _require_object(receipt.get("action_record"), "action_record")
        seq = action_record.get("chain_seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise ReceiptError(f"seq {index}: missing or invalid chain_seq")
        chain_prev_hash = _require_string(
            action_record.get("chain_prev_hash"), "chain_prev_hash"
        )
        if index == 0:
            if action_record.get("key_transition") is not None:
                return _broken_chain(
                    seq,
                    f"seq {seq}: chain starts at a key_transition segment "
                    "without the prior segment",
                )
            try:
                verify_action_receipt(receipt, state["cur_key"])
            except ReceiptError as exc:
                return _broken_chain(seq, f"seq {seq}: signature: {exc}")
            result = _validate_action_genesis(action_record, chain_prev_hash, seq)
            if result is not None:
                return result
            state["segment_base_seq"] = seq
        elif action_record.get("key_transition") is not None:
            result = _start_rotated_segment(
                receipt, action_record, seq, index, state, trusted_keys, allow_unpinned
            )
            if result is not None:
                return result
            try:
                verify_action_receipt(receipt, state["cur_key"])
            except ReceiptError as exc:
                return _broken_chain(seq, f"seq {seq}: signature: {exc}")
        else:
            try:
                verify_action_receipt(receipt, state["cur_key"])
            except ReceiptError as exc:
                return _broken_chain(seq, f"seq {seq}: signature: {exc}")
            if seq == 0:
                return _broken_chain(
                    seq,
                    f"seq {seq}: unexpected seq 0 without a key_transition boundary",
                )
            expected_seq = state["segment_base_seq"] + (
                index - state["segment_start_index"]
            )
            if seq != expected_seq:
                return _broken_chain(
                    seq, f"seq gap: expected {expected_seq}, got {seq}"
                )
            if chain_prev_hash != state["prev_hash"]:
                return _broken_chain(seq, f"seq {seq}: chain_prev_hash mismatch")
        expected_seq = state["segment_base_seq"] + (
            index - state["segment_start_index"]
        )
        if seq != expected_seq:
            return _broken_chain(seq, f"seq gap: expected {expected_seq}, got {seq}")
        state["segment_receipt_count"] += 1
        result = _validate_closed_run(action_record, seq, state)
        if result is not None:
            return result
        result = _validate_session_control_state(action_record, seq, index, state)
        if result is not None:
            return result
        open_record = _session_open(action_record.get("session_control"))
        if open_record is not None:
            active_run_nonce = _require_string(
                open_record.get("run_nonce"), "session_control.open.run_nonce"
            )
            active_open_nonce = _require_string(
                open_record.get("open_nonce"), "session_control.open.open_nonce"
            )
            state["active_run_nonce"] = active_run_nonce
            state["active_open_nonce"] = active_open_nonce
            state["opened_runs"].add(active_run_nonce)
            state["closed_runs"].discard(active_run_nonce)
        elif _session_close(action_record.get("session_control")) is not None:
            if state["active_run_nonce"] is not None:
                state["closed_runs"].add(state["active_run_nonce"])
            state["active_run_nonce"] = None
            state["active_open_nonce"] = None
        state["prev_hash"] = receipt_hash(receipt)
        state["prior_segment_seq"] = seq
    return {
        "valid": True,
        "unpinned": (not key_hex and allow_unpinned) or None,
        "receipt_count": len(receipts),
        "final_seq": receipts[-1].get("action_record", {}).get("chain_seq", 0),
        "root_hash": state["prev_hash"],
    }


def _validate_action_genesis(
    action_record: dict[str, Any], chain_prev_hash: str, seq: int
) -> dict[str, Any] | None:
    open_record = _session_open(action_record.get("session_control"))
    if chain_prev_hash.startswith(GENESIS_SESSION_OPEN_PREFIX):
        if open_record is None:
            return _broken_chain(
                seq, "seq 0: g1 chain_prev_hash requires session_control.open"
            )
        if seq != 0:
            return _broken_chain(
                seq, "seq 0: bound session_open genesis must be chain_seq 0"
            )
        computed = compute_session_open_genesis(open_record)
        if chain_prev_hash != computed:
            return _broken_chain(seq, "seq 0: session_open genesis hash mismatch")
        if open_record.get("genesis_hash") != computed:
            return _broken_chain(seq, "seq 0: session_open genesis_hash mismatch")
        if open_record.get("chain_open_seq") != seq:
            return _broken_chain(
                seq,
                "seq 0: session_open chain_open_seq does not match receipt chain_seq",
            )
        if (
            open_record.get("prior_chain_head", "") != ""
            or open_record.get("prior_chain_seq", 0) != 0
        ):
            return _broken_chain(
                seq, "seq 0: bound genesis session_open must not carry prior chain tail"
            )
        return None
    if chain_prev_hash != GENESIS_HASH:
        return _broken_chain(
            seq,
            "seq 0: genesis receipt chain_prev_hash must be genesis or a bound "
            "session_open g1 hash",
        )
    if open_record is not None:
        return _broken_chain(
            seq,
            "seq 0: session_open on legacy genesis must use bound g1 chain_prev_hash",
        )
    return None


def _parse_trusted_keys(key_hex: str) -> set[str]:
    return {key.strip().lower() for key in key_hex.split(",") if key.strip()}


def _start_rotated_segment(
    receipt: dict[str, Any],
    action_record: dict[str, Any],
    seq: int,
    index: int,
    state: dict[str, Any],
    trusted_keys: set[str],
    allow_unpinned: bool,
) -> dict[str, Any] | None:
    marker = _require_object(action_record.get("key_transition"), "key_transition")
    if seq != 0:
        return _broken_chain(
            seq, f"seq {seq}: key_transition marker on a non-genesis receipt (seq != 0)"
        )
    if marker.get("prior_chain_hash") != state["prev_hash"]:
        return _broken_chain(
            seq,
            f"seq {seq}: key_transition prior_chain_hash does not match actual "
            "prior tail hash",
        )
    if action_record.get("chain_prev_hash") != state["prev_hash"]:
        return _broken_chain(
            seq,
            f"seq {seq}: segment-genesis chain_prev_hash does not match prior "
            "tail hash",
        )
    if marker.get("prior_signer_key") != state["cur_key"]:
        return _broken_chain(
            seq,
            f"seq {seq}: key_transition prior_signer_key does not match prior "
            "segment key",
        )
    if marker.get("prior_chain_seq") != state["prior_segment_seq"]:
        return _broken_chain(
            seq,
            f"seq {seq}: key_transition prior_chain_seq does not match prior "
            "segment final seq",
        )
    signer_key = _require_string(receipt.get("signer_key"), "signer_key").lower()
    if trusted_keys:
        if signer_key not in trusted_keys:
            return _broken_chain(
                seq, f"seq {seq}: signer key {signer_key} is not in the trusted set"
            )
    elif not allow_unpinned or signer_key != state["cur_key"]:
        return _broken_chain(
            seq, f"seq {seq}: signer key {signer_key} is not in the trusted set"
        )
    state["cur_key"] = signer_key
    state["segment_start_index"] = index
    state["segment_base_seq"] = 0
    state["segment_receipt_count"] = 0
    return None


def _validate_closed_run(
    action_record: dict[str, Any], seq: int, state: dict[str, Any]
) -> dict[str, Any] | None:
    if _session_open(action_record.get("session_control")) is not None:
        return None
    run_nonce = action_record.get("run_nonce")
    if not isinstance(run_nonce, str) or run_nonce == "":
        return None
    if run_nonce not in state["opened_runs"]:
        return _broken_chain(
            seq, f"seq {seq}: run_nonce first receipt is not a matching session_open"
        )
    if run_nonce in state["closed_runs"]:
        return _broken_chain(seq, f"seq {seq}: record observed after session_close")
    return None


def _validate_session_control_state(
    action_record: dict[str, Any],
    seq: int,
    index: int,
    state: dict[str, Any],
) -> dict[str, Any] | None:
    session_control = action_record.get("session_control")
    if not isinstance(session_control, dict):
        return None
    kind = session_control.get("kind")
    payload_count = sum(
        1
        for name in ("open", "heartbeat", "close")
        if session_control.get(name) is not None
    )
    if payload_count != 1:
        return _broken_chain(
            seq, f"seq {seq}: session_control must carry exactly one payload"
        )
    action_run_nonce = action_record.get("run_nonce")
    if not isinstance(action_run_nonce, str) or action_run_nonce == "":
        return _broken_chain(
            seq, f"seq {seq}: session_control receipt missing run_nonce"
        )
    control_run_nonce = None
    if kind == "session_open" and isinstance(session_control.get("open"), dict):
        control_run_nonce = session_control["open"].get("run_nonce")
    elif kind == "heartbeat" and isinstance(session_control.get("heartbeat"), dict):
        control_run_nonce = session_control["heartbeat"].get("run_nonce")
    elif kind == "session_close" and isinstance(session_control.get("close"), dict):
        control_run_nonce = session_control["close"].get("run_nonce")
    if control_run_nonce != action_run_nonce:
        return _broken_chain(seq, f"seq {seq}: session_control run_nonce mismatch")
    if kind == "session_open" and index > 0:
        open_record = _require_object(
            session_control.get("open"), "session_control.open"
        )
        run_nonce = open_record.get("run_nonce")
        if run_nonce in state["opened_runs"]:
            return _broken_chain(
                seq, f"seq {seq}: duplicate session_open for run_nonce"
            )
        if open_record.get("chain_open_seq") != seq:
            return _broken_chain(
                seq,
                f"seq {seq}: session_open chain_open_seq does not match "
                "receipt chain_seq",
            )
        if open_record.get("prior_chain_head", "") != state["prev_hash"]:
            return _broken_chain(
                seq,
                f"seq {seq}: session_open prior_chain_head does not match chain tail",
            )
        if open_record.get("prior_chain_seq", 0) != state["prior_segment_seq"]:
            return _broken_chain(
                seq,
                f"seq {seq}: session_open prior_chain_seq does not match previous seq",
            )
        return None
    if kind == "heartbeat":
        heartbeat = _require_object(
            session_control.get("heartbeat"), "session_control.heartbeat"
        )
        if state["active_run_nonce"] is None or state["active_open_nonce"] is None:
            return _broken_chain(
                seq, f"seq {seq}: heartbeat has no active session_open"
            )
        if heartbeat.get("run_nonce") != state["active_run_nonce"]:
            return _broken_chain(seq, f"seq {seq}: heartbeat run_nonce mismatch")
        if heartbeat.get("open_nonce") != state["active_open_nonce"]:
            return _broken_chain(seq, f"seq {seq}: heartbeat open_nonce mismatch")
        if heartbeat.get("chain_head") != state["prev_hash"]:
            return _broken_chain(seq, f"seq {seq}: heartbeat chain_head mismatch")
        if heartbeat.get("chain_seq_head") != seq - 1:
            return _broken_chain(seq, f"seq {seq}: heartbeat chain_seq_head mismatch")
    elif kind == "session_close":
        close = _require_object(session_control.get("close"), "session_control.close")
        if state["active_run_nonce"] is None or state["active_open_nonce"] is None:
            return _broken_chain(
                seq, f"seq {seq}: session_close has no active session_open"
            )
        if close.get("run_nonce") != state["active_run_nonce"]:
            return _broken_chain(seq, f"seq {seq}: session_close run_nonce mismatch")
        if close.get("open_nonce") != state["active_open_nonce"]:
            return _broken_chain(seq, f"seq {seq}: session_close open_nonce mismatch")
        if close.get("root_hash") != state["prev_hash"]:
            return _broken_chain(seq, f"seq {seq}: session_close root_hash mismatch")
        if close.get("final_seq") != seq:
            return _broken_chain(seq, f"seq {seq}: session_close final_seq mismatch")
        if close.get("receipt_count") != state["segment_receipt_count"]:
            return _broken_chain(
                seq, f"seq {seq}: session_close receipt_count mismatch"
            )
    return None


def receipt_hash(receipt: dict[str, Any]) -> str:
    if receipt.get("record_type") == V2_RECORD_TYPE:
        return hashlib.sha256(canonicalize(receipt)).hexdigest()
    return hashlib.sha256(_canonicalize_receipt(receipt)).hexdigest()


def _broken_chain(seq: int, error: str) -> dict[str, Any]:
    return {
        "valid": False,
        "receipt_count": 0,
        "final_seq": 0,
        "error": error,
        "broken_at_seq": seq,
    }


def _signature_signer_key_id(receipt: dict[str, Any]) -> str:
    signature = _require_object(receipt.get("signature"), "signature")
    return _require_string(signature.get("signer_key_id"), "signature.signer_key_id")


def _canonicalize_action_record(action_record: dict[str, Any]) -> bytes:
    return _canonical_json(_order_struct(action_record, _ACTION_RECORD_FIELDS))


def compute_session_open_genesis(open_record: dict[str, Any]) -> str:
    h = hashlib.sha256()

    def frame(data: bytes) -> None:
        h.update(struct.pack(">Q", len(data)))
        h.update(data)

    def text_field(name: str) -> bytes:
        value = open_record.get(name, "")
        return value.encode("utf-8") if isinstance(value, str) else b""

    frame(SESSION_OPEN_GENESIS_LABEL.encode("utf-8"))
    frame(text_field("run_nonce"))
    frame(text_field("open_nonce"))
    frame(text_field("recorder_session"))
    frame(text_field("policy_hash"))
    frame(text_field("signer_key_epoch"))
    hb_secs_raw = open_record.get("heartbeat_seconds", 0)
    if (
        not isinstance(hb_secs_raw, int)
        or isinstance(hb_secs_raw, bool)
        or hb_secs_raw < 0
    ):
        hb_secs = 0
    elif hb_secs_raw > MAX_UINT64:
        raise ReceiptError("session_control.open.heartbeat_seconds must be a uint64")
    else:
        hb_secs = hb_secs_raw
    frame(struct.pack(">Q", hb_secs))
    frame(text_field("genesis_anchor_head"))
    frame(text_field("genesis_anchor_log"))
    frame(text_field("posture_capsule_sha256"))
    frame(text_field("containment_nonce"))
    frame(text_field("contained_uid"))
    return GENESIS_SESSION_OPEN_PREFIX + h.hexdigest()


def _canonicalize_receipt(receipt: dict[str, Any]) -> bytes:
    return _canonical_json(_order_struct(receipt, _RECEIPT_FIELDS))


def _canonical_json(value: Any) -> bytes:
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    encoded = (
        encoded.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    return encoded.encode("utf-8")


def _order_struct(
    value: dict[str, Any],
    fields: tuple[tuple[str, bool, str | None], ...],
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, omitempty, nested in fields:
        if name not in value:
            if omitempty:
                continue
            field_value = _zero_value(name, nested)
        else:
            field_value = value[name]
        if nested == "action_record" and isinstance(field_value, dict):
            field_value = _order_struct(field_value, _ACTION_RECORD_FIELDS)
        elif nested == "redaction" and isinstance(field_value, dict):
            field_value = _order_struct(field_value, _REDACTION_FIELDS)
        elif nested == "shield" and isinstance(field_value, dict):
            field_value = _order_struct(field_value, _SHIELD_FIELDS)
        elif nested == "taint_source" and isinstance(field_value, list):
            field_value = [
                _order_struct(item, _TAINT_SOURCE_FIELDS)
                if isinstance(item, dict)
                else item
                for item in field_value
            ]
        elif nested == "key_transition" and isinstance(field_value, dict):
            field_value = _order_struct(field_value, _KEY_TRANSITION_FIELDS)
        elif nested == "session_control" and isinstance(field_value, dict):
            field_value = _order_struct(field_value, _SESSION_CONTROL_FIELDS)
        elif nested == "session_open" and isinstance(field_value, dict):
            field_value = _order_struct(field_value, _SESSION_OPEN_FIELDS)
        elif nested == "session_heartbeat" and isinstance(field_value, dict):
            field_value = _order_struct(field_value, _SESSION_HEARTBEAT_FIELDS)
        elif nested == "session_close" and isinstance(field_value, dict):
            field_value = _order_struct(field_value, _SESSION_CLOSE_FIELDS)
        else:
            field_value = _normalize_maps(field_value)
        if omitempty and _is_go_zero(field_value):
            continue
        out[name] = field_value
    return out


def _field_names(fields: tuple[tuple[str, bool, str | None], ...]) -> set[str]:
    return {name for name, _, _ in fields}


def _zero_value(name: str, nested: str | None) -> Any:
    if nested == "action_record":
        return {}
    if name in {
        "version",
        "chain_seq",
        "level",
        "prior_chain_seq",
        "heartbeat_seconds",
        "chain_open_seq",
        "beat",
        "chain_seq_head",
        "fsync_errors_gated",
        "durability_blocks",
        "final_seq",
        "receipt_count",
    }:
        return 0
    if name == "delegation_chain":
        return None
    if name == "timestamp":
        return "0001-01-01T00:00:00Z"
    return ""


def _is_go_zero(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return not value
    if isinstance(value, int | float):
        return value == 0
    if isinstance(value, str):
        return value == ""
    if isinstance(value, list | tuple | dict):
        return len(value) == 0
    return False


def _normalize_maps(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalize_maps(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize_maps(value[key]) for key in sorted(value)}
    return value


def verify_evidence_receipt(
    receipt: dict[str, Any], expected_key_hex: str = ""
) -> None:
    normalize_evidence_receipt(receipt)
    signature = _require_object(receipt.get("signature"), "signature")
    _require_string(signature.get("signer_key_id"), "signature.signer_key_id")
    key_hex = expected_key_hex.lower()
    if not key_hex:
        raise ReceiptError("EvidenceReceipt v2 verification requires --key")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(binascii.unhexlify(key_hex))
        sig = binascii.unhexlify(
            _require_string(signature.get("signature"), "signature.signature")[
                len(SIGNATURE_PREFIX) :
            ]
        )
    except (binascii.Error, ValueError) as exc:
        raise ReceiptError(f"invalid signature key or bytes: {exc}") from exc
    try:
        public_key.verify(sig, _evidence_preimage(receipt))
    except InvalidSignature as exc:
        raise ReceiptError("signature verification failed") from exc


def verify_action_receipt(receipt: dict[str, Any], expected_key_hex: str = "") -> None:
    normalize_action_receipt(receipt)
    signer_key = _require_string(receipt.get("signer_key"), "signer_key").lower()
    expected = expected_key_hex.lower()
    key_hex = expected or signer_key
    if expected and signer_key != expected:
        raise ReceiptError(
            f"signer_key {signer_key} does not match expected key {expected}"
        )
    try:
        public_key = Ed25519PublicKey.from_public_bytes(binascii.unhexlify(key_hex))
        sig = binascii.unhexlify(
            _require_string(receipt.get("signature"), "signature")[
                len(SIGNATURE_PREFIX) :
            ]
        )
    except (binascii.Error, ValueError) as exc:
        raise ReceiptError(f"invalid signature key or bytes: {exc}") from exc
    digest = hashlib.sha256(
        _canonicalize_action_record(
            _require_object(receipt.get("action_record"), "action_record")
        )
    ).digest()
    try:
        public_key.verify(sig, digest)
    except InvalidSignature as exc:
        raise ReceiptError("signature verification failed") from exc


def normalize_action_receipt(receipt: dict[str, Any]) -> None:
    # EV2-FU-1: the single tolerated unknown top-level surface is the advisory
    # ext bag. It is unsigned (the signature covers only the canonical action
    # record) and never consulted, so it is accepted here but deliberately kept
    # out of _RECEIPT_FIELDS (the canonical/hash preimage) rather than added to
    # it. Every other unrecognized field is rejected by _reject_unknown.
    _reject_unknown(receipt, _field_names(_RECEIPT_FIELDS) | {"ext"}, "receipt")
    if receipt.get("version") != 1:
        raise ReceiptError(
            f"unsupported receipt version {receipt.get('version')} (expected 1)"
        )
    validate_action_record(
        _require_object(receipt.get("action_record"), "action_record")
    )
    signature = _require_string(receipt.get("signature"), "signature")
    if not signature.startswith(SIGNATURE_PREFIX):
        raise ReceiptError(
            f"invalid signature format: missing {SIGNATURE_PREFIX} prefix"
        )
    _require_hex(signature[len(SIGNATURE_PREFIX) :], 64, "signature")
    _require_string(receipt.get("signer_key"), "signer_key")


def validate_action_record(action_record: dict[str, Any]) -> None:
    _reject_unknown(action_record, _field_names(_ACTION_RECORD_FIELDS), "action_record")
    if action_record.get("version") != 1:
        raise ReceiptError(
            f"unsupported action record version {action_record.get('version')} "
            "(expected 1)"
        )
    _require_string(action_record.get("action_id"), "action_id")
    action_type = _require_string(action_record.get("action_type"), "action_type")
    if action_type not in _VALID_ACTION_TYPES:
        raise ReceiptError(f"invalid action_type {action_type}")
    _require_string(action_record.get("timestamp"), "timestamp")
    _require_string(action_record.get("target"), "target")
    _require_string(action_record.get("verdict"), "verdict")
    _require_string(action_record.get("transport"), "transport")
    _require_string(action_record.get("chain_prev_hash"), "chain_prev_hash")
    _require_non_negative_int(action_record.get("chain_seq"), "chain_seq")
    run_nonce = action_record.get("run_nonce")
    if run_nonce is not None:
        _require_run_nonce(run_nonce, "run_nonce")
    _validate_optional_action_structs(action_record)


def _validate_optional_action_structs(action_record: dict[str, Any]) -> None:
    redaction = action_record.get("redaction")
    if redaction is not None:
        _reject_unknown(
            _require_object(redaction, "redaction"),
            _field_names(_REDACTION_FIELDS),
            "redaction",
        )

    shield = action_record.get("shield")
    if shield is not None:
        _reject_unknown(
            _require_object(shield, "shield"),
            _field_names(_SHIELD_FIELDS),
            "shield",
        )

    key_transition = action_record.get("key_transition")
    if key_transition is not None:
        _reject_unknown(
            _require_object(key_transition, "key_transition"),
            _field_names(_KEY_TRANSITION_FIELDS),
            "key_transition",
        )

    session_control = action_record.get("session_control")
    if session_control is not None:
        _validate_session_control(_require_object(session_control, "session_control"))

    taint_sources = action_record.get("recent_taint_sources")
    if taint_sources is not None:
        if not isinstance(taint_sources, list):
            raise ReceiptError("recent_taint_sources must be a list when provided")
        for index, source in enumerate(taint_sources):
            _reject_unknown(
                _require_object(source, f"recent_taint_sources[{index}]"),
                _field_names(_TAINT_SOURCE_FIELDS),
                f"recent_taint_sources[{index}]",
            )


def _validate_session_control(session_control: dict[str, Any]) -> None:
    _reject_unknown(
        session_control,
        _field_names(_SESSION_CONTROL_FIELDS),
        "session_control",
    )
    kind = _require_string(session_control.get("kind"), "session_control.kind")
    payloads = 0
    for name in ("open", "heartbeat", "close"):
        if session_control.get(name) is not None:
            payloads += 1
    if payloads != 1:
        raise ReceiptError("session_control must carry exactly one payload")
    if kind == "session_open":
        _validate_session_open(session_control.get("open"))
    elif kind == "heartbeat":
        _validate_session_heartbeat(session_control.get("heartbeat"))
    elif kind == "session_close":
        _validate_session_close(session_control.get("close"))
    else:
        raise ReceiptError("unknown session_control kind")


def _validate_session_open(value: Any) -> None:
    open_record = _require_object(value, "session_control.open")
    _reject_unknown(
        open_record, _field_names(_SESSION_OPEN_FIELDS), "session_control.open"
    )
    _require_run_nonce(open_record.get("run_nonce"), "session_control.open.run_nonce")
    _require_string(open_record.get("open_nonce"), "session_control.open.open_nonce")
    _require_string(
        open_record.get("recorder_session"), "session_control.open.recorder_session"
    )
    _require_policy_hash(
        open_record.get("policy_hash"), "session_control.open.policy_hash"
    )
    _require_string(
        open_record.get("signer_key_epoch"), "session_control.open.signer_key_epoch"
    )
    _require_uint64(
        open_record.get("heartbeat_seconds"),
        "session_control.open.heartbeat_seconds",
    )
    _require_uint64(
        open_record.get("chain_open_seq"), "session_control.open.chain_open_seq"
    )
    _require_optional_string(
        open_record.get("prior_chain_head"), "session_control.open.prior_chain_head"
    )
    if "prior_chain_seq" in open_record:
        _require_uint64(
            open_record.get("prior_chain_seq"), "session_control.open.prior_chain_seq"
        )
    if "genesis_hash" in open_record:
        genesis_hash = _require_string(
            open_record.get("genesis_hash"), "session_control.open.genesis_hash"
        )
        if not genesis_hash.startswith(GENESIS_SESSION_OPEN_PREFIX):
            raise ReceiptError("session_control.open.genesis_hash must start with g1:")
    _require_optional_string(
        open_record.get("genesis_anchor_head"),
        "session_control.open.genesis_anchor_head",
    )
    _require_optional_string(
        open_record.get("genesis_anchor_log"),
        "session_control.open.genesis_anchor_log",
    )
    if "posture_capsule_sha256" in open_record:
        _require_sha256(
            open_record.get("posture_capsule_sha256"),
            "session_control.open.posture_capsule_sha256",
        )
    _require_optional_string(
        open_record.get("posture_signer_key_id"),
        "session_control.open.posture_signer_key_id",
    )
    _require_optional_string(
        open_record.get("containment_nonce"),
        "session_control.open.containment_nonce",
    )
    _require_optional_string(
        open_record.get("contained_uid"), "session_control.open.contained_uid"
    )


def _validate_session_heartbeat(value: Any) -> None:
    heartbeat = _require_object(value, "session_control.heartbeat")
    _reject_unknown(
        heartbeat, _field_names(_SESSION_HEARTBEAT_FIELDS), "session_control.heartbeat"
    )
    _require_run_nonce(
        heartbeat.get("run_nonce"), "session_control.heartbeat.run_nonce"
    )
    _require_string(heartbeat.get("open_nonce"), "session_control.heartbeat.open_nonce")
    _require_uint64(heartbeat.get("beat"), "session_control.heartbeat.beat")
    _require_string(heartbeat.get("chain_head"), "session_control.heartbeat.chain_head")
    _require_uint64(
        heartbeat.get("chain_seq_head"), "session_control.heartbeat.chain_seq_head"
    )
    _require_string(
        heartbeat.get("heartbeat_time"), "session_control.heartbeat.heartbeat_time"
    )
    _require_uint64(
        heartbeat.get("fsync_errors_gated"),
        "session_control.heartbeat.fsync_errors_gated",
    )
    _require_uint64(
        heartbeat.get("durability_blocks"),
        "session_control.heartbeat.durability_blocks",
    )


def _validate_session_close(value: Any) -> None:
    close = _require_object(value, "session_control.close")
    _reject_unknown(close, _field_names(_SESSION_CLOSE_FIELDS), "session_control.close")
    _require_run_nonce(close.get("run_nonce"), "session_control.close.run_nonce")
    _require_string(close.get("open_nonce"), "session_control.close.open_nonce")
    _require_uint64(close.get("final_seq"), "session_control.close.final_seq")
    _require_string(close.get("root_hash"), "session_control.close.root_hash")
    _require_uint64(close.get("receipt_count"), "session_control.close.receipt_count")
    _require_string(close.get("close_reason"), "session_control.close.close_reason")
    _require_uint64(
        close.get("fsync_errors_gated"), "session_control.close.fsync_errors_gated"
    )
    _require_uint64(
        close.get("durability_blocks"), "session_control.close.durability_blocks"
    )


def _session_open(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    if value.get("kind") != "session_open":
        return None
    open_record = value.get("open")
    return open_record if isinstance(open_record, dict) else None


def _session_close(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    if value.get("kind") != "session_close":
        return None
    close_record = value.get("close")
    return close_record if isinstance(close_record, dict) else None


def normalize_evidence_receipt(receipt: dict[str, Any]) -> None:
    _reject_unknown(receipt, _ENVELOPE_FIELDS, "receipt")
    if _require_string(receipt.get("record_type"), "record_type") != V2_RECORD_TYPE:
        raise ReceiptError("unsupported record_type for v2 verifier")
    if receipt.get("receipt_version") != 2:
        raise ReceiptError("EvidenceReceipt requires receipt_version=2")
    payload_kind = _require_string(receipt.get("payload_kind"), "payload_kind")
    if payload_kind in _RESERVED_PAYLOAD_KINDS:
        raise ReceiptError(f"payload_kind {payload_kind} is known but not implemented")
    if payload_kind not in _PAYLOAD_KINDS:
        raise ReceiptError(f"unknown payload_kind {payload_kind}")
    _validate_canonicalization(receipt.get("canonicalization"))
    _validate_crit(receipt.get("crit"), payload_kind)
    _require_string(receipt.get("event_id"), "event_id")
    _require_string(receipt.get("timestamp"), "timestamp")
    _require_non_negative_int(receipt.get("chain_seq"), "chain_seq")
    _require_string(receipt.get("chain_prev_hash"), "chain_prev_hash")
    if payload_kind in _POLICY_HASH_PAYLOAD_KINDS:
        _require_policy_hash(receipt.get("policy_hash"), "policy_hash")
    _validate_signature(receipt, payload_kind)
    payload = _require_object(receipt.get("payload"), "payload")
    if payload_kind == "proxy_decision":
        _validate_proxy_decision_payload(payload)
    elif payload_kind == "proxy_decision_with_spans":
        _validate_proxy_decision_with_spans_payload(payload)


def _validate_canonicalization(value: Any) -> None:
    canonicalization = _require_object(value, "canonicalization")
    _reject_unknown(canonicalization, _CANONICALIZATION_FIELDS, "canonicalization")
    if (
        _require_string(
            canonicalization.get("jcs_profile"), "canonicalization.jcs_profile"
        )
        != V2_JCS_PROFILE
    ):
        raise ReceiptError("canonicalization.jcs_profile is invalid")
    if (
        _require_string(
            canonicalization.get("jcs_version"), "canonicalization.jcs_version"
        )
        != V2_JCS_VERSION
    ):
        raise ReceiptError("canonicalization.jcs_version is invalid")
    if (
        _require_string(canonicalization.get("hash_alg"), "canonicalization.hash_alg")
        != V2_HASH_ALG
    ):
        raise ReceiptError("canonicalization.hash_alg is invalid")
    if (
        _require_string(canonicalization.get("sig_alg"), "canonicalization.sig_alg")
        != V2_SIGNATURE_ALGORITHM
    ):
        raise ReceiptError("canonicalization.sig_alg is invalid")
    if (
        _require_string(
            canonicalization.get("redaction_ruleset_id"),
            "canonicalization.redaction_ruleset_id",
        )
        != V2_REDACTION_RULESET_ID
    ):
        raise ReceiptError("canonicalization.redaction_ruleset_id is invalid")
    if (
        _require_string(
            canonicalization.get("redaction_ruleset_version"),
            "canonicalization.redaction_ruleset_version",
        )
        != V2_REDACTION_RULESET_VERSION
    ):
        raise ReceiptError("canonicalization.redaction_ruleset_version is invalid")
    if (
        _require_string(
            canonicalization.get("redaction_ruleset_hash"),
            "canonicalization.redaction_ruleset_hash",
        )
        != V2_REDACTION_RULESET_HASH
    ):
        raise ReceiptError("canonicalization.redaction_ruleset_hash is invalid")


def _validate_crit(value: Any, payload_kind: str) -> None:
    crit = _require_string_list(value, "crit")
    seen: set[str] = set()
    has_canonicalization = False
    has_source_spans = False
    for name in crit:
        if name == "":
            raise ReceiptError("crit has an empty name")
        if name in seen:
            raise ReceiptError(f"crit has duplicate {name}")
        seen.add(name)
        if name == CRIT_CANONICALIZATION:
            has_canonicalization = True
        elif name == CRIT_SOURCE_SPANS:
            has_source_spans = True
        else:
            raise ReceiptError(f"crit has unknown field {name}")
    if not has_canonicalization:
        raise ReceiptError("crit must include canonicalization")
    if payload_kind == "proxy_decision_with_spans" and not has_source_spans:
        raise ReceiptError("crit must include source_spans")
    if payload_kind != "proxy_decision_with_spans" and has_source_spans:
        raise ReceiptError(f"crit source_spans is invalid for {payload_kind}")


def _validate_signature(receipt: dict[str, Any], payload_kind: str) -> None:
    signature = _require_object(receipt.get("signature"), "signature")
    _reject_unknown(signature, _SIGNATURE_FIELDS, "signature")
    _require_string(signature.get("signer_key_id"), "signature.signer_key_id")
    if (
        _require_string(signature.get("key_purpose"), "signature.key_purpose")
        != "receipt-signing"
    ):
        raise ReceiptError(
            f"signature.key_purpose is not authorized for {payload_kind}"
        )
    if (
        _require_string(signature.get("algorithm"), "signature.algorithm")
        != V2_SIGNATURE_ALGORITHM
    ):
        raise ReceiptError("signature.algorithm is invalid")
    sig = _require_string(signature.get("signature"), "signature.signature")
    if not sig.startswith(SIGNATURE_PREFIX):
        raise ReceiptError(
            f"invalid signature format: missing {SIGNATURE_PREFIX} prefix"
        )
    _require_hex(sig[len(SIGNATURE_PREFIX) :], 64, "signature.signature")


def _validate_proxy_decision_payload(payload: dict[str, Any]) -> None:
    _reject_unknown(payload, _PROXY_DECISION_FIELDS, "payload")
    _validate_proxy_decision_base(payload)


def _validate_proxy_decision_base(payload: dict[str, Any]) -> None:
    _require_string(payload.get("action_type"), "action_type")
    _require_string(payload.get("target"), "target")
    _require_string(payload.get("verdict"), "verdict")
    _require_string(payload.get("transport"), "transport")
    _require_string_list(payload.get("policy_sources"), "policy_sources")
    _require_string(payload.get("winning_source"), "winning_source")


def _validate_proxy_decision_with_spans_payload(payload: dict[str, Any]) -> None:
    _reject_unknown(payload, _PROXY_DECISION_FIELDS | {"source_spans"}, "payload")
    _validate_proxy_decision_base(payload)
    spans = payload.get("source_spans")
    if not isinstance(spans, list) or not spans:
        raise ReceiptError("source_spans is required")
    for index, span in enumerate(spans):
        _validate_source_span(span, index)


def _validate_source_span(value: Any, index: int) -> None:
    span = _require_object(value, f"source_spans[{index}]")
    _reject_unknown(span, _SOURCE_SPAN_FIELDS, f"source_spans[{index}]")
    _require_string(span.get("source_id"), f"source_spans[{index}].source_id")
    source_kind = _require_string(
        span.get("source_kind"), f"source_spans[{index}].source_kind"
    )
    if source_kind not in _SOURCE_KINDS:
        raise ReceiptError(f"source_spans[{index}].source_kind is invalid")
    view = _require_string(
        span.get("normalized_view"), f"source_spans[{index}].normalized_view"
    )
    if view not in _NORMALIZED_VIEWS and not _has_dlp_normalized_suffix(view):
        raise ReceiptError(f"source_spans[{index}].normalized_view is invalid")
    _require_sha256(
        span.get("pipelock_binary_digest"),
        f"source_spans[{index}].pipelock_binary_digest",
    )
    _require_sha256(
        span.get("rules_bundle_digest"), f"source_spans[{index}].rules_bundle_digest"
    )
    _require_transform_profile(
        span.get("transform_profile"),
        f"source_spans[{index}].transform_profile",
    )
    _require_policy_hash(span.get("policy_hash"), f"source_spans[{index}].policy_hash")
    _require_string(span.get("rule_id"), f"source_spans[{index}].rule_id")
    _require_optional_string(span.get("bundle"), f"source_spans[{index}].bundle")
    _require_optional_string(
        span.get("bundle_version"), f"source_spans[{index}].bundle_version"
    )
    _require_optional_string(
        span.get("redacted_sample"), f"source_spans[{index}].redacted_sample"
    )
    _require_hmac_hash(span.get("match_hash"), f"source_spans[{index}].match_hash")
    if (
        _require_string(
            span.get("match_hash_alg"), f"source_spans[{index}].match_hash_alg"
        )
        != "hmac-sha256"
    ):
        raise ReceiptError(f"source_spans[{index}].match_hash_alg is invalid")
    _require_string(span.get("match_class"), f"source_spans[{index}].match_class")
    has_offset = "char_offset" in span
    has_length = "char_length" in span
    if has_offset != has_length:
        raise ReceiptError(
            f"source_spans[{index}] must pair char_offset and char_length"
        )
    if has_offset:
        _require_non_negative_int(
            span.get("char_offset"), f"source_spans[{index}].char_offset"
        )
        length = _require_non_negative_int(
            span.get("char_length"), f"source_spans[{index}].char_length"
        )
        if length <= 0:
            raise ReceiptError(f"source_spans[{index}].char_length must be positive")
        if (
            view != "sanitized_target"
            and view != "dlp_normalized"
            and not view.startswith("dlp_normalized:")
        ):
            raise ReceiptError(
                f"source_spans[{index}].char_offset not allowed for normalized_view"
            )


def _evidence_preimage(receipt: dict[str, Any]) -> bytes:
    clone = dict(receipt)
    clone["signature"] = {
        "signer_key_id": "",
        "key_purpose": "",
        "algorithm": "",
        "signature": "",
    }
    return canonicalize(clone)


def _reject_unknown(value: dict[str, Any], allowed: set[str], label: str) -> None:
    for key in value:
        if key not in allowed:
            raise ReceiptError(f"{label}: unknown field {key}")


def _require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptError(f"{name} is required")
    return value


def _require_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ReceiptError(f"{name} is required")
    return value


def _require_optional_string(value: Any, name: str) -> None:
    if value is not None and not isinstance(value, str):
        raise ReceiptError(f"{name} must be a string when provided")


def _require_non_negative_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReceiptError(f"{name} must be a non-negative integer")
    return value


def _require_uint64(value: Any, name: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > MAX_UINT64
    ):
        raise ReceiptError(f"{name} must be a uint64")
    return value


def _require_run_nonce(value: Any, name: str) -> str:
    run_nonce = _require_string(value, name)
    if len(run_nonce) != 32 or any(ch not in "0123456789abcdef" for ch in run_nonce):
        raise ReceiptError(f"{name} must be 32 lowercase hex chars")
    return run_nonce


def _require_string_list(value: Any, name: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(v, str) for v in value)
    ):
        raise ReceiptError(f"{name} is required")
    return value


def _require_hex(value: str, byte_len: int, name: str) -> None:
    try:
        raw = binascii.unhexlify(value)
    except (binascii.Error, ValueError) as exc:
        raise ReceiptError(f"{name} must be hex: {exc}") from exc
    if len(raw) != byte_len:
        raise ReceiptError(f"{name} length = {len(raw)}, want {byte_len}")


def _require_sha256(value: Any, name: str) -> None:
    digest = _require_string(value, name)
    if not digest.startswith("sha256:"):
        raise ReceiptError(f"{name} must be sha256:<64 hex>")
    _require_hex(digest[len("sha256:") :], 32, name)


def _require_policy_hash(value: Any, name: str) -> None:
    digest = _require_string(value, name)
    if not digest.startswith("sha256:"):
        raise ReceiptError(f"{name} must be sha256:<64 lowercase hex>")
    raw = digest[len("sha256:") :]
    if len(raw) != 64 or any(ch not in "0123456789abcdef" for ch in raw):
        raise ReceiptError(f"{name} must be sha256:<64 lowercase hex>")


def _require_hmac_hash(value: Any, name: str) -> None:
    digest = _require_string(value, name)
    if not digest.startswith("hmac-sha256:"):
        raise ReceiptError(f"{name} must be hmac-sha256:<64 hex>")
    _require_hex(digest[len("hmac-sha256:") :], 32, name)


def _require_transform_profile(value: Any, name: str) -> None:
    profile = _require_string(value, name)
    prefix = "pipelock-transform-v"
    version = profile.removeprefix(prefix)
    if version == profile or not version.isdecimal():
        raise ReceiptError(f"{name} must be pipelock-transform-vN")


def _has_dlp_normalized_suffix(view: str) -> bool:
    prefix = "dlp_normalized:"
    return view.startswith(prefix) and len(view) > len(prefix)
