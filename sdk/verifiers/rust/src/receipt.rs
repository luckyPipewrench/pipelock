use crate::signing::verify_receipt;
use crate::types::ReceiptReport;
use crate::util::{parse_json_file, resolve_signer_key, string_at, u64_at, Result};
use std::path::{Path, PathBuf};

pub fn run_receipt(pathname: &str, signer_key: &str) -> Result<ReceiptReport> {
    let clean = PathBuf::from(pathname);
    let key_hex = resolve_signer_key(signer_key)?;
    let receipt = parse_json_file(Path::new(&clean))?;
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
    match verify_receipt(&receipt, &key_hex) {
        Ok(()) => report.valid = true,
        Err(err) => report.error = Some(err),
    }
    Ok(report)
}
