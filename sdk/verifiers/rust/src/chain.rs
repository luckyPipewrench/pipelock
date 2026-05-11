use crate::canonical::canonicalize_receipt;
use crate::signing::verify_receipt;
use crate::types::{ChainResult, Receipt, Totals};
use crate::util::sha256_hex;

pub const GENESIS_HASH: &str = "genesis";

pub fn receipt_hash(receipt: &Receipt) -> String {
    sha256_hex(&canonicalize_receipt(receipt))
}

/// Verify receipt ordering, signatures, and prev-hash linkage.
///
/// When expected_key_hex is empty, the first receipt's signer_key pins the chain key.
/// Callers that require external trust must pass a non-empty expected key.
pub fn verify_chain(receipts: &[Receipt], expected_key_hex: &str) -> ChainResult {
    if receipts.is_empty() {
        return ChainResult {
            valid: true,
            receipt_count: 0,
            final_seq: 0,
            root_hash: String::new(),
            error: None,
            broken_at_seq: None,
        };
    }

    let mut key_hex = expected_key_hex.to_string();
    if key_hex.is_empty() {
        key_hex = receipts[0]
            .get("signer_key")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
    }

    let mut prev_hash = GENESIS_HASH.to_string();
    for (index, receipt) in receipts.iter().enumerate() {
        let Some(seq) = receipt
            .get("action_record")
            .and_then(|record| record.get("chain_seq"))
            .and_then(|value| value.as_u64())
        else {
            return broken(index as u64, format!("seq {index}: missing or invalid chain_seq"));
        };
        if let Err(err) = verify_receipt(receipt, &key_hex) {
            return broken(seq, format!("seq {seq}: signature: {err}"));
        }
        if seq != index as u64 {
            return broken(seq, format!("seq gap: expected {index}, got {seq}"));
        }
        let chain_prev_hash = receipt
            .get("action_record")
            .and_then(|record| record.get("chain_prev_hash"))
            .and_then(|value| value.as_str());
        if chain_prev_hash != Some(prev_hash.as_str()) {
            return broken(seq, format!("seq {seq}: chain_prev_hash mismatch"));
        }
        prev_hash = receipt_hash(receipt);
    }

    ChainResult {
        valid: true,
        receipt_count: receipts.len(),
        final_seq: (receipts.len() - 1) as u64,
        root_hash: prev_hash,
        error: None,
        broken_at_seq: None,
    }
}

pub fn compute_totals(receipts: &[Receipt]) -> Totals {
    let mut totals = Totals::zero();
    for receipt in receipts {
        let verdict = receipt
            .get("action_record")
            .and_then(|record| record.get("verdict"))
            .and_then(|value| value.as_str())
            .unwrap_or("");
        totals.add_verdict(verdict);
    }
    totals
}

fn broken(seq: u64, error: String) -> ChainResult {
    ChainResult {
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        root_hash: String::new(),
        error: Some(error),
        broken_at_seq: Some(seq),
    }
}
