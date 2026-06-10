use crate::signing::{
    normalize_evidence_receipt, verify_receipt_with_options, UNPINNED_RECEIPT_BANNER,
};
use crate::types::ReceiptReport;
use crate::util::{
    parse_json_text, reject_duplicate_keys, resolve_signer_key, string_at, u64_at, Result,
    VerifierError,
};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

pub fn run_receipt(
    pathname: &str,
    signer_key: &str,
    allow_unpinned: bool,
) -> Result<ReceiptReport> {
    let clean = PathBuf::from(pathname);
    let key_hex = resolve_signer_key(signer_key)?;
    // Read the raw text so duplicate-key detection sees every key occurrence,
    // not the last-wins map serde_json would build.
    let text = fs::read_to_string(&clean)
        .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", clean.display())))?;
    let mut report = ReceiptReport {
        path: clean.display().to_string(),
        valid: false,
        unpinned: None,
        action_id: None,
        verdict: None,
        transport: None,
        signer_key: None,
        policy_hash: None,
        chain_seq: None,
        error: None,
    };
    // Reject duplicate object keys before parsing or populating report
    // metadata. Last-wins parsing would otherwise let attacker-controlled
    // duplicate values leak into the displayed rejection report.
    if let Err(err) = reject_duplicate_keys(&text) {
        report.error = Some(err.to_string());
        return Ok(report);
    }
    let receipt: Value = parse_json_text(&text, "malformed JSON")?;
    if string_at(&receipt, &["record_type"]) == Some("evidence_receipt_v2") {
        report.action_id = string_at(&receipt, &["event_id"]).map(str::to_string);
        report.verdict = string_at(&receipt, &["payload", "verdict"]).map(str::to_string);
        report.transport = string_at(&receipt, &["payload", "transport"]).map(str::to_string);
        report.signer_key = Some(key_hex.clone());
        report.policy_hash = string_at(&receipt, &["policy_hash"]).map(str::to_string);
        report.chain_seq = u64_at(&receipt, &["chain_seq"]);
    } else {
        report.action_id = string_at(&receipt, &["action_record", "action_id"]).map(str::to_string);
        report.verdict = string_at(&receipt, &["action_record", "verdict"]).map(str::to_string);
        report.transport = string_at(&receipt, &["action_record", "transport"]).map(str::to_string);
        report.signer_key = string_at(&receipt, &["signer_key"]).map(str::to_string);
        report.policy_hash =
            string_at(&receipt, &["action_record", "policy_hash"]).map(str::to_string);
        report.chain_seq = u64_at(&receipt, &["action_record", "chain_seq"]);
    }
    let is_v2 = string_at(&receipt, &["record_type"]) == Some("evidence_receipt_v2");
    if key_hex.is_empty() && is_v2 {
        match normalize_evidence_receipt(&receipt) {
            Ok(()) => {
                report.valid = allow_unpinned;
                report.unpinned = Some(true);
                report.error = Some(UNPINNED_RECEIPT_BANNER.to_string());
            }
            Err(err) => report.error = Some(err),
        }
        return Ok(report);
    }
    match verify_receipt_with_options(&receipt, &key_hex, allow_unpinned) {
        Ok(()) => {
            report.valid = true;
            if key_hex.is_empty() {
                report.unpinned = Some(true);
                report.error = Some(UNPINNED_RECEIPT_BANNER.to_string());
            }
        }
        Err(err) => report.error = Some(err),
    }
    Ok(report)
}
