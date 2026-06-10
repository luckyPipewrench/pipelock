use crate::canonical::{canonicalize_action_record, canonicalize_jcs_value};
use crate::types::Receipt;
use crate::util::{decode_hex, VerifierError};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const SIGNATURE_PREFIX: &str = "ed25519:";
pub const UNPINNED_RECEIPT_BANNER: &str =
    "UNPINNED — signature is self-consistent but the signer was NOT checked against a trusted key";
const V2_RECORD_TYPE: &str = "evidence_receipt_v2";
const V2_SIGNATURE_ALGORITHM: &str = "ed25519";
const V2_KEY_PURPOSE: &str = "receipt-signing";
const V2_JCS_PROFILE: &str = "pipelock-jcs-rfc8785-nfc-v1";
const V2_JCS_VERSION: &str = "rfc8785";
const V2_HASH_ALG: &str = "sha256";
const V2_REDACTION_RULESET_ID: &str = "pipelock-transform-v1";
const V2_REDACTION_RULESET_VERSION: &str = "1";
const V2_REDACTION_RULESET_HASH: &str =
    "sha256:541896788b42651a202448894583a847db9d1aa081c33a7e1f0512303d72527e";
const CRIT_CANONICALIZATION: &str = "canonicalization";
const CRIT_SOURCE_SPANS: &str = "source_spans";
const VALID_ACTION_TYPES: &[&str] = &[
    "read",
    "derive",
    "write",
    "delegate",
    "authorize",
    "spend",
    "commit",
    "actuate",
    "unclassified",
];

pub fn verify_receipt(
    receipt: &Receipt,
    expected_key_hex: &str,
) -> std::result::Result<(), String> {
    verify_receipt_with_options(receipt, expected_key_hex, false)
}

pub fn verify_receipt_with_options(
    receipt: &Receipt,
    expected_key_hex: &str,
    allow_unpinned: bool,
) -> std::result::Result<(), String> {
    if receipt.get("record_type").and_then(|value| value.as_str()) == Some(V2_RECORD_TYPE) {
        return verify_evidence_receipt(receipt, expected_key_hex);
    }
    normalize_receipt(receipt)?;
    let signer_key = receipt
        .get("signer_key")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let expected = expected_key_hex.to_ascii_lowercase();
    if expected.is_empty() && !allow_unpinned {
        return Err(UNPINNED_RECEIPT_BANNER.to_string());
    }
    let key_hex = if expected.is_empty() {
        signer_key.as_str()
    } else {
        expected.as_str()
    };
    if !expected.is_empty() && signer_key != expected {
        return Err(format!(
            "signer_key {signer_key} does not match expected key {expected}"
        ));
    }

    let pub_key = decode_hex(key_hex, 32, "signer_key")?;
    let signature = require_string(receipt.get("signature"), "signature")?;
    if !signature.starts_with(SIGNATURE_PREFIX) {
        return Err(format!(
            "invalid signature format: missing {SIGNATURE_PREFIX} prefix"
        ));
    }
    let sig_bytes = decode_hex(&signature[SIGNATURE_PREFIX.len()..], 64, "signature")?;
    let action_record = receipt
        .get("action_record")
        .ok_or_else(|| "action_record is required".to_string())?;
    let digest = Sha256::digest(canonicalize_action_record(action_record));
    let pub_key: [u8; 32] = pub_key
        .try_into()
        .map_err(|_| "invalid signer_key length".to_string())?;
    let verifying_key =
        VerifyingKey::from_bytes(&pub_key).map_err(|err| format!("invalid signer_key: {err}"))?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|err| format!("invalid signature: {err}"))?;
    verifying_key
        .verify_strict(&digest, &signature)
        .map_err(|_| "signature verification failed".to_string())
}

pub fn verify_evidence_receipt(
    receipt: &Receipt,
    expected_key_hex: &str,
) -> std::result::Result<(), String> {
    normalize_evidence_receipt(receipt)?;
    let signature_obj = receipt
        .get("signature")
        .and_then(|value| value.as_object())
        .ok_or_else(|| "signature is required".to_string())?;
    require_string(
        signature_obj.get("signer_key_id"),
        "signature.signer_key_id",
    )?;
    let key_hex = expected_key_hex.to_ascii_lowercase();
    if key_hex.is_empty() {
        return Err("EvidenceReceipt v2 verification requires --key".to_string());
    }
    let pub_key = decode_hex(&key_hex, 32, "signer_key_id")?;
    let signature = require_string(signature_obj.get("signature"), "signature.signature")?;
    if !signature.starts_with(SIGNATURE_PREFIX) {
        return Err(format!(
            "invalid signature format: missing {SIGNATURE_PREFIX} prefix"
        ));
    }
    let sig_bytes = decode_hex(&signature[SIGNATURE_PREFIX.len()..], 64, "signature")?;
    let pub_key: [u8; 32] = pub_key
        .try_into()
        .map_err(|_| "invalid signer_key_id length".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pub_key)
        .map_err(|err| format!("invalid signer_key_id: {err}"))?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|err| format!("invalid signature: {err}"))?;
    verifying_key
        .verify_strict(&evidence_preimage(receipt)?, &signature)
        .map_err(|_| "signature verification failed".to_string())
}

pub fn normalize_evidence_receipt(receipt: &Receipt) -> std::result::Result<(), String> {
    reject_unknown_fields(
        receipt,
        &[
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
        ],
        "receipt",
    )?;
    if require_string(receipt.get("record_type"), "record_type")? != V2_RECORD_TYPE {
        return Err("unsupported record_type for v2 verifier".to_string());
    }
    if receipt
        .get("receipt_version")
        .and_then(|value| value.as_u64())
        != Some(2)
    {
        return Err("EvidenceReceipt requires receipt_version=2".to_string());
    }
    let payload_kind = require_string(receipt.get("payload_kind"), "payload_kind")?;
    if reserved_payload_kind(payload_kind) {
        return Err(format!(
            "payload_kind {payload_kind} is known but not implemented"
        ));
    }
    if !valid_payload_kind(payload_kind) {
        return Err(format!("unknown payload_kind {payload_kind}"));
    }
    validate_canonicalization(receipt.get("canonicalization"))?;
    validate_crit(receipt.get("crit"), payload_kind)?;
    require_string(receipt.get("event_id"), "event_id")?;
    require_string(receipt.get("timestamp"), "timestamp")?;
    require_non_negative_integer(receipt.get("chain_seq"), "chain_seq")?;
    require_string(receipt.get("chain_prev_hash"), "chain_prev_hash")?;
    require_policy_hash(receipt.get("policy_hash"), "policy_hash")?;
    validate_v2_signature(receipt, payload_kind)?;
    let payload = receipt
        .get("payload")
        .ok_or_else(|| "payload is required".to_string())?;
    match payload_kind {
        "proxy_decision" => validate_proxy_decision_payload(payload),
        "proxy_decision_with_spans" => validate_proxy_decision_with_spans_payload(payload),
        _ => Ok(()),
    }
}

fn validate_canonicalization(value: Option<&serde_json::Value>) -> std::result::Result<(), String> {
    let canonicalization = value
        .and_then(|value| value.as_object())
        .ok_or_else(|| "canonicalization is required".to_string())?;
    reject_unknown_object_fields(
        canonicalization,
        &[
            "jcs_profile",
            "jcs_version",
            "hash_alg",
            "sig_alg",
            "redaction_ruleset_id",
            "redaction_ruleset_version",
            "redaction_ruleset_hash",
        ],
        "canonicalization",
    )?;
    if require_string(
        canonicalization.get("jcs_profile"),
        "canonicalization.jcs_profile",
    )? != V2_JCS_PROFILE
    {
        return Err("canonicalization.jcs_profile is invalid".to_string());
    }
    if require_string(
        canonicalization.get("jcs_version"),
        "canonicalization.jcs_version",
    )? != V2_JCS_VERSION
    {
        return Err("canonicalization.jcs_version is invalid".to_string());
    }
    if require_string(
        canonicalization.get("hash_alg"),
        "canonicalization.hash_alg",
    )? != V2_HASH_ALG
    {
        return Err("canonicalization.hash_alg is invalid".to_string());
    }
    if require_string(canonicalization.get("sig_alg"), "canonicalization.sig_alg")?
        != V2_SIGNATURE_ALGORITHM
    {
        return Err("canonicalization.sig_alg is invalid".to_string());
    }
    if require_string(
        canonicalization.get("redaction_ruleset_id"),
        "canonicalization.redaction_ruleset_id",
    )? != V2_REDACTION_RULESET_ID
    {
        return Err("canonicalization.redaction_ruleset_id is invalid".to_string());
    }
    if require_string(
        canonicalization.get("redaction_ruleset_version"),
        "canonicalization.redaction_ruleset_version",
    )? != V2_REDACTION_RULESET_VERSION
    {
        return Err("canonicalization.redaction_ruleset_version is invalid".to_string());
    }
    if require_string(
        canonicalization.get("redaction_ruleset_hash"),
        "canonicalization.redaction_ruleset_hash",
    )? != V2_REDACTION_RULESET_HASH
    {
        return Err("canonicalization.redaction_ruleset_hash is invalid".to_string());
    }
    Ok(())
}

fn validate_crit(
    value: Option<&serde_json::Value>,
    payload_kind: &str,
) -> std::result::Result<(), String> {
    let crit = value
        .and_then(|value| value.as_array())
        .ok_or_else(|| "crit is required".to_string())?;
    if crit.is_empty() {
        return Err("crit is required".to_string());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut has_canonicalization = false;
    let mut has_source_spans = false;
    for value in crit {
        let name = value
            .as_str()
            .ok_or_else(|| "crit is required".to_string())?;
        if name.is_empty() {
            return Err("crit has an empty name".to_string());
        }
        if !seen.insert(name) {
            return Err(format!("crit has duplicate {name}"));
        }
        match name {
            CRIT_CANONICALIZATION => has_canonicalization = true,
            CRIT_SOURCE_SPANS => has_source_spans = true,
            _ => return Err(format!("crit has unknown field {name}")),
        }
    }
    if !has_canonicalization {
        return Err("crit must include canonicalization".to_string());
    }
    if payload_kind == "proxy_decision_with_spans" && !has_source_spans {
        return Err("crit must include source_spans".to_string());
    }
    if payload_kind != "proxy_decision_with_spans" && has_source_spans {
        return Err(format!("crit source_spans is invalid for {payload_kind}"));
    }
    Ok(())
}

fn validate_v2_signature(receipt: &Receipt, payload_kind: &str) -> std::result::Result<(), String> {
    let signature = receipt
        .get("signature")
        .and_then(|value| value.as_object())
        .ok_or_else(|| "signature is required".to_string())?;
    reject_unknown_object_fields(
        signature,
        &["signer_key_id", "key_purpose", "algorithm", "signature"],
        "signature",
    )?;
    require_string(signature.get("signer_key_id"), "signature.signer_key_id")?;
    let purpose = require_string(signature.get("key_purpose"), "signature.key_purpose")?;
    if purpose != V2_KEY_PURPOSE {
        return Err(format!(
            "signature.key_purpose {purpose} is not authorized for {payload_kind}"
        ));
    }
    if require_string(signature.get("algorithm"), "signature.algorithm")? != V2_SIGNATURE_ALGORITHM
    {
        return Err("signature.algorithm is invalid".to_string());
    }
    let signature_value = require_string(signature.get("signature"), "signature.signature")?;
    if !signature_value.starts_with(SIGNATURE_PREFIX) {
        return Err(format!(
            "invalid signature format: missing {SIGNATURE_PREFIX} prefix"
        ));
    }
    decode_hex(&signature_value[SIGNATURE_PREFIX.len()..], 64, "signature")?;
    Ok(())
}

fn evidence_preimage(receipt: &Receipt) -> std::result::Result<Vec<u8>, String> {
    let mut clone = receipt.clone();
    let obj = clone
        .as_object_mut()
        .ok_or_else(|| "receipt is required".to_string())?;
    obj.insert(
        "signature".to_string(),
        serde_json::json!({
            "signer_key_id": "",
            "key_purpose": "",
            "algorithm": "",
            "signature": ""
        }),
    );
    canonicalize_jcs_value(&clone)
}

pub fn normalize_receipt(receipt: &Receipt) -> std::result::Result<(), String> {
    let version = receipt.get("version").and_then(|value| value.as_u64());
    if version != Some(1) {
        return Err(format!(
            "unsupported receipt version {} (expected 1)",
            receipt
                .get("version")
                .map_or_else(|| "null".to_string(), serde_json::Value::to_string)
        ));
    }
    let action_record = receipt
        .get("action_record")
        .ok_or_else(|| "action_record is required".to_string())?;
    validate_action_record(action_record)?;
    require_string(receipt.get("signature"), "signature")?;
    require_string(receipt.get("signer_key"), "signer_key")?;
    Ok(())
}

pub fn validate_action_record(
    action_record: &serde_json::Value,
) -> std::result::Result<(), String> {
    let version = action_record
        .get("version")
        .and_then(|value| value.as_u64());
    if version != Some(1) {
        return Err(format!(
            "unsupported action record version {} (expected 1)",
            action_record
                .get("version")
                .map_or_else(|| "null".to_string(), serde_json::Value::to_string)
        ));
    }
    require_string(action_record.get("action_id"), "action_id")?;
    let action_type = require_string(action_record.get("action_type"), "action_type")?;
    if !VALID_ACTION_TYPES.contains(&action_type) {
        return Err(format!("invalid action_type {action_type}"));
    }
    require_string(action_record.get("timestamp"), "timestamp")?;
    require_string(action_record.get("target"), "target")?;
    require_string(action_record.get("verdict"), "verdict")?;
    require_string(action_record.get("transport"), "transport")?;
    require_string(action_record.get("chain_prev_hash"), "chain_prev_hash")?;
    require_non_negative_integer(action_record.get("chain_seq"), "chain_seq")?;
    Ok(())
}

fn require_string<'a>(
    value: Option<&'a serde_json::Value>,
    name: &str,
) -> std::result::Result<&'a str, String> {
    match value.and_then(|value| value.as_str()) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(format!("{name} is required")),
    }
}

fn reject_unknown_fields(
    value: &serde_json::Value,
    allowed: &[&str],
    label: &str,
) -> std::result::Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} is required"))?;
    reject_unknown_object_fields(object, allowed, label)
}

fn reject_unknown_object_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    label: &str,
) -> std::result::Result<(), String> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("{label}: unknown field {key}"));
        }
    }
    Ok(())
}

fn require_non_negative_integer(
    value: Option<&serde_json::Value>,
    name: &str,
) -> std::result::Result<u64, String> {
    value
        .and_then(|value| value.as_u64())
        .ok_or_else(|| format!("{name} must be a non-negative integer"))
}

fn require_string_array(
    value: Option<&serde_json::Value>,
    name: &str,
) -> std::result::Result<(), String> {
    let items = value
        .and_then(|value| value.as_array())
        .ok_or_else(|| format!("{name} is required"))?;
    if items.is_empty() || items.iter().any(|item| !item.is_string()) {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

fn valid_payload_kind(kind: &str) -> bool {
    matches!(kind, "proxy_decision" | "proxy_decision_with_spans")
}

fn reserved_payload_kind(kind: &str) -> bool {
    matches!(kind, "defer_opened" | "defer_resolved")
}

fn validate_proxy_decision_payload(payload: &serde_json::Value) -> std::result::Result<(), String> {
    reject_unknown_fields(
        payload,
        &[
            "action_type",
            "target",
            "verdict",
            "live_verdict",
            "transport",
            "policy_sources",
            "winning_source",
            "rule_id",
        ],
        "payload",
    )?;
    validate_proxy_decision_base(payload)
}

fn validate_proxy_decision_base(payload: &serde_json::Value) -> std::result::Result<(), String> {
    require_string(payload.get("action_type"), "action_type")?;
    require_string(payload.get("target"), "target")?;
    require_string(payload.get("verdict"), "verdict")?;
    require_string(payload.get("transport"), "transport")?;
    require_string_array(payload.get("policy_sources"), "policy_sources")?;
    require_string(payload.get("winning_source"), "winning_source")?;
    Ok(())
}

fn validate_proxy_decision_with_spans_payload(
    payload: &serde_json::Value,
) -> std::result::Result<(), String> {
    reject_unknown_fields(
        payload,
        &[
            "action_type",
            "target",
            "verdict",
            "live_verdict",
            "transport",
            "policy_sources",
            "winning_source",
            "rule_id",
            "source_spans",
        ],
        "payload",
    )?;
    validate_proxy_decision_base(payload)?;
    let spans = payload
        .get("source_spans")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "source_spans is required".to_string())?;
    if spans.is_empty() {
        return Err("source_spans is required".to_string());
    }
    for (index, span) in spans.iter().enumerate() {
        validate_source_span(span, index)?;
    }
    Ok(())
}

fn validate_source_span(span: &serde_json::Value, index: usize) -> std::result::Result<(), String> {
    reject_unknown_fields(
        span,
        &[
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
        ],
        &format!("source_spans[{index}]"),
    )?;
    require_string(
        span.get("source_id"),
        &format!("source_spans[{index}].source_id"),
    )?;
    let source_kind = require_string(
        span.get("source_kind"),
        &format!("source_spans[{index}].source_kind"),
    )?;
    if !matches!(
        source_kind,
        "http_request_url" | "http_response" | "mcp_tool_result" | "mcp_tool_args"
    ) {
        return Err(format!("source_spans[{index}].source_kind is invalid"));
    }
    let view = require_string(
        span.get("normalized_view"),
        &format!("source_spans[{index}].normalized_view"),
    )?;
    if !valid_normalized_view(view) {
        return Err(format!("source_spans[{index}].normalized_view is invalid"));
    }
    require_sha256_digest(
        span.get("pipelock_binary_digest"),
        &format!("source_spans[{index}].pipelock_binary_digest"),
    )?;
    require_sha256_digest(
        span.get("rules_bundle_digest"),
        &format!("source_spans[{index}].rules_bundle_digest"),
    )?;
    require_transform_profile(
        span.get("transform_profile"),
        &format!("source_spans[{index}].transform_profile"),
    )?;
    require_policy_hash(
        span.get("policy_hash"),
        &format!("source_spans[{index}].policy_hash"),
    )?;
    require_string(
        span.get("rule_id"),
        &format!("source_spans[{index}].rule_id"),
    )?;
    require_hmac_match_hash(
        span.get("match_hash"),
        &format!("source_spans[{index}].match_hash"),
    )?;
    if require_string(
        span.get("match_hash_alg"),
        &format!("source_spans[{index}].match_hash_alg"),
    )? != "hmac-sha256"
    {
        return Err(format!("source_spans[{index}].match_hash_alg is invalid"));
    }
    require_string(
        span.get("match_class"),
        &format!("source_spans[{index}].match_class"),
    )?;
    let has_offset = span.get("char_offset").is_some();
    let has_length = span.get("char_length").is_some();
    if has_offset != has_length {
        return Err(format!(
            "source_spans[{index}] must pair char_offset and char_length"
        ));
    }
    if has_offset {
        require_non_negative_integer(
            span.get("char_offset"),
            &format!("source_spans[{index}].char_offset"),
        )?;
        let length = require_non_negative_integer(
            span.get("char_length"),
            &format!("source_spans[{index}].char_length"),
        )?;
        if length == 0 {
            return Err(format!(
                "source_spans[{index}].char_length must be positive"
            ));
        }
        if !offsets_allowed_for_view(view) {
            return Err(format!(
                "source_spans[{index}].char_offset not allowed for normalized_view"
            ));
        }
    }
    Ok(())
}

fn valid_normalized_view(view: &str) -> bool {
    matches!(
        view,
        "sanitized_target"
            | "for_matching"
            | "for_matching:invisible_spaced"
            | "leetspeak:for_matching"
            | "vowel_fold:for_matching"
            | "for_matching:base64_decoded"
            | "for_matching:hex_decoded"
            | "dlp_normalized"
    ) || view
        .strip_prefix("dlp_normalized:")
        .is_some_and(|suffix| !suffix.is_empty())
}

fn offsets_allowed_for_view(view: &str) -> bool {
    view == "sanitized_target" || view == "dlp_normalized" || view.starts_with("dlp_normalized:")
}

fn require_sha256_digest(
    value: Option<&serde_json::Value>,
    name: &str,
) -> std::result::Result<(), String> {
    let digest = require_string(value, name)?;
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(format!("{name} must be sha256:<64 hex>"));
    };
    if hex.len() != 64 || hex::decode(hex).is_err() {
        return Err(format!("{name} must be sha256:<64 hex>"));
    }
    Ok(())
}

fn require_policy_hash(
    value: Option<&serde_json::Value>,
    name: &str,
) -> std::result::Result<(), String> {
    let digest = require_string(value, name)?;
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(format!("{name} must be sha256:<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be sha256:<64 lowercase hex>"));
    }
    Ok(())
}

fn require_hmac_match_hash(
    value: Option<&serde_json::Value>,
    name: &str,
) -> std::result::Result<(), String> {
    let digest = require_string(value, name)?;
    let Some(hex) = digest.strip_prefix("hmac-sha256:") else {
        return Err(format!("{name} must be hmac-sha256:<64 hex>"));
    };
    if hex.len() != 64 || hex::decode(hex).is_err() {
        return Err(format!("{name} must be hmac-sha256:<64 hex>"));
    }
    Ok(())
}

fn require_transform_profile(
    value: Option<&serde_json::Value>,
    name: &str,
) -> std::result::Result<(), String> {
    let profile = require_string(value, name)?;
    let Some(version) = profile.strip_prefix("pipelock-transform-v") else {
        return Err(format!("{name} must be pipelock-transform-vN"));
    };
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{name} must be pipelock-transform-vN"));
    }
    Ok(())
}

pub fn receipt_error(err: String) -> VerifierError {
    VerifierError::Invalid(err)
}
