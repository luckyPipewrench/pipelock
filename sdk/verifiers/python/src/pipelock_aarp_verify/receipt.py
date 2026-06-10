# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""EvidenceReceipt v2 verifier used by the cross-language conformance gate."""

from __future__ import annotations

import binascii
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonicalize

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
EVIDENCE_ENTRY_TYPE = "evidence_receipt"
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


class ReceiptError(Exception):
    """Receipt parsing, validation, or signature verification failed."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ReceiptError(f"duplicate object key: {key}")
        out[key] = value
    return out


def load_receipt(path: str | Path) -> dict[str, Any]:
    data = Path(path).read_text(encoding="utf-8")
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
            raise ReceiptError("Python verifier supports EvidenceReceipt v2 only")
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
    for index, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        raw = line.strip()
        if raw == "":
            continue
        try:
            entry = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
        except ReceiptError:
            raise
        except json.JSONDecodeError as exc:
            raise ReceiptError(f"line {index}: malformed JSON: {exc}") from exc
        if not isinstance(entry, dict):
            raise ReceiptError(f"line {index}: recorder entry must be an object")
        if entry.get("type") != EVIDENCE_ENTRY_TYPE:
            continue
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
        "unpinned": (not key_hex) or None,
        "receipt_count": len(receipts),
        "final_seq": receipts[-1].get("chain_seq", 0),
        "root_hash": prev_hash,
    }


def receipt_hash(receipt: dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize(receipt)).hexdigest()


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


def verify_evidence_receipt(receipt: dict[str, Any], expected_key_hex: str = "") -> None:
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
    if _require_string(canonicalization.get("jcs_profile"), "canonicalization.jcs_profile") != V2_JCS_PROFILE:
        raise ReceiptError("canonicalization.jcs_profile is invalid")
    if _require_string(canonicalization.get("jcs_version"), "canonicalization.jcs_version") != V2_JCS_VERSION:
        raise ReceiptError("canonicalization.jcs_version is invalid")
    if _require_string(canonicalization.get("hash_alg"), "canonicalization.hash_alg") != V2_HASH_ALG:
        raise ReceiptError("canonicalization.hash_alg is invalid")
    if _require_string(canonicalization.get("sig_alg"), "canonicalization.sig_alg") != V2_SIGNATURE_ALGORITHM:
        raise ReceiptError("canonicalization.sig_alg is invalid")
    if (
        _require_string(canonicalization.get("redaction_ruleset_id"), "canonicalization.redaction_ruleset_id")
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
        _require_string(canonicalization.get("redaction_ruleset_hash"), "canonicalization.redaction_ruleset_hash")
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
    if _require_string(signature.get("key_purpose"), "signature.key_purpose") != "receipt-signing":
        raise ReceiptError(f"signature.key_purpose is not authorized for {payload_kind}")
    if _require_string(signature.get("algorithm"), "signature.algorithm") != V2_SIGNATURE_ALGORITHM:
        raise ReceiptError("signature.algorithm is invalid")
    sig = _require_string(signature.get("signature"), "signature.signature")
    if not sig.startswith(SIGNATURE_PREFIX):
        raise ReceiptError(f"invalid signature format: missing {SIGNATURE_PREFIX} prefix")
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
    source_kind = _require_string(span.get("source_kind"), f"source_spans[{index}].source_kind")
    if source_kind not in _SOURCE_KINDS:
        raise ReceiptError(f"source_spans[{index}].source_kind is invalid")
    view = _require_string(span.get("normalized_view"), f"source_spans[{index}].normalized_view")
    if view not in _NORMALIZED_VIEWS and not _has_dlp_normalized_suffix(view):
        raise ReceiptError(f"source_spans[{index}].normalized_view is invalid")
    _require_sha256(span.get("pipelock_binary_digest"), f"source_spans[{index}].pipelock_binary_digest")
    _require_sha256(span.get("rules_bundle_digest"), f"source_spans[{index}].rules_bundle_digest")
    _require_transform_profile(
        span.get("transform_profile"),
        f"source_spans[{index}].transform_profile",
    )
    _require_policy_hash(span.get("policy_hash"), f"source_spans[{index}].policy_hash")
    _require_string(span.get("rule_id"), f"source_spans[{index}].rule_id")
    _require_optional_string(span.get("bundle"), f"source_spans[{index}].bundle")
    _require_optional_string(span.get("bundle_version"), f"source_spans[{index}].bundle_version")
    _require_optional_string(span.get("redacted_sample"), f"source_spans[{index}].redacted_sample")
    _require_hmac_hash(span.get("match_hash"), f"source_spans[{index}].match_hash")
    if _require_string(span.get("match_hash_alg"), f"source_spans[{index}].match_hash_alg") != "hmac-sha256":
        raise ReceiptError(f"source_spans[{index}].match_hash_alg is invalid")
    _require_string(span.get("match_class"), f"source_spans[{index}].match_class")
    has_offset = "char_offset" in span
    has_length = "char_length" in span
    if has_offset != has_length:
        raise ReceiptError(f"source_spans[{index}] must pair char_offset and char_length")
    if has_offset:
        _require_non_negative_int(span.get("char_offset"), f"source_spans[{index}].char_offset")
        length = _require_non_negative_int(span.get("char_length"), f"source_spans[{index}].char_length")
        if length <= 0:
            raise ReceiptError(f"source_spans[{index}].char_length must be positive")
        if view != "sanitized_target" and view != "dlp_normalized" and not view.startswith("dlp_normalized:"):
            raise ReceiptError(f"source_spans[{index}].char_offset not allowed for normalized_view")


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


def _require_string_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(v, str) for v in value):
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
