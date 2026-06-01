use crate::signing::verify_receipt;
use crate::types::ReceiptReport;
use crate::util::{
    reject_duplicate_keys, resolve_signer_key, string_at, u64_at, Result, VerifierError,
};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

pub fn run_receipt(pathname: &str, signer_key: &str) -> Result<ReceiptReport> {
    let clean = PathBuf::from(pathname);
    let key_hex = resolve_signer_key(signer_key)?;
    // Read the raw text so duplicate-key detection sees every key occurrence,
    // not the last-wins map serde_json would build.
    let text = fs::read_to_string(&clean)
        .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", clean.display())))?;
    let receipt: Value = serde_json::from_str(&text)
        .map_err(|err| VerifierError::Runtime(format!("malformed JSON: {err}")))?;
    let mut report = ReceiptReport {
        path: clean.display().to_string(),
        valid: false,
        action_id: string_at(&receipt, &["action_record", "action_id"]).map(str::to_string),
        verdict: string_at(&receipt, &["action_record", "verdict"]).map(str::to_string),
        transport: string_at(&receipt, &["action_record", "transport"]).map(str::to_string),
        signer_key: string_at(&receipt, &["signer_key"]).map(str::to_string),
        policy_hash: string_at(&receipt, &["action_record", "policy_hash"]).map(str::to_string),
        chain_seq: u64_at(&receipt, &["action_record", "chain_seq"]),
        error: None,
    };
    // Reject duplicate object keys before signature verification. Treated as an
    // invalid receipt (report.valid stays false → exit 1), matching the Go and
    // Python verifiers.
    if let Err(err) = reject_duplicate_keys(&text) {
        report.error = Some(err.to_string());
        return Ok(report);
    }
    match verify_receipt(&receipt, &key_hex) {
        Ok(()) => report.valid = true,
        Err(err) => report.error = Some(err),
    }
    Ok(report)
}
