use crate::canonical::canonicalize_action_record;
use crate::types::Receipt;
use crate::util::{decode_hex, VerifierError};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const SIGNATURE_PREFIX: &str = "ed25519:";
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

pub fn verify_receipt(receipt: &Receipt, expected_key_hex: &str) -> std::result::Result<(), String> {
    normalize_receipt(receipt)?;
    let signer_key = receipt
        .get("signer_key")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let expected = expected_key_hex.to_ascii_lowercase();
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
    let signature = Signature::from_slice(&sig_bytes).map_err(|err| format!("invalid signature: {err}"))?;
    verifying_key
        .verify_strict(&digest, &signature)
        .map_err(|_| "signature verification failed".to_string())
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

pub fn validate_action_record(action_record: &serde_json::Value) -> std::result::Result<(), String> {
    let version = action_record.get("version").and_then(|value| value.as_u64());
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

fn require_non_negative_integer(
    value: Option<&serde_json::Value>,
    name: &str,
) -> std::result::Result<u64, String> {
    value
        .and_then(|value| value.as_u64())
        .ok_or_else(|| format!("{name} must be a non-negative integer"))
}

pub fn receipt_error(err: String) -> VerifierError {
    VerifierError::Invalid(err)
}
