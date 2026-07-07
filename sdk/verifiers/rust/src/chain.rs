use crate::canonical::{canonicalize_jcs_value, canonicalize_receipt};
use crate::signing::{
    normalize_evidence_receipt, verify_receipt, verify_receipt_with_options,
    UNPINNED_RECEIPT_BANNER,
};
use crate::types::{ChainResult, Receipt, Totals};
use crate::util::sha256_hex;
use sha2::{Digest, Sha256};

pub const GENESIS_HASH: &str = "genesis";
pub const GENESIS_SESSION_OPEN_PREFIX: &str = "g1:";
const SESSION_OPEN_GENESIS_LABEL: &str = "pipelock.receipt.session_open.v1";
const EVIDENCE_RECORD_TYPE: &str = "evidence_receipt_v2";

pub fn receipt_hash(receipt: &Receipt) -> String {
    if receipt
        .get("record_type")
        .and_then(serde_json::Value::as_str)
        == Some(EVIDENCE_RECORD_TYPE)
    {
        return sha256_hex(
            &canonicalize_jcs_value(receipt).expect("validated evidence receipt canonicalizes"),
        );
    }
    sha256_hex(&canonicalize_receipt(receipt))
}

/// Verify receipt ordering, signatures, and prev-hash linkage.
///
/// When expected_key_hex is empty, the first receipt's signer_key pins the chain key.
/// Callers that require external trust must pass a non-empty expected key.
pub fn verify_chain(receipts: &[Receipt], expected_key_hex: &str) -> ChainResult {
    verify_chain_with_options(receipts, expected_key_hex, false)
}

pub fn verify_chain_with_options(
    receipts: &[Receipt],
    expected_key_hex: &str,
    allow_unpinned: bool,
) -> ChainResult {
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

    if receipts[0]
        .get("record_type")
        .and_then(serde_json::Value::as_str)
        == Some(EVIDENCE_RECORD_TYPE)
    {
        return verify_evidence_chain(receipts, expected_key_hex, allow_unpinned);
    }

    let mut key_hex = expected_key_hex.to_string();
    if key_hex.is_empty() && !allow_unpinned {
        return broken(0, UNPINNED_RECEIPT_BANNER.to_string());
    }
    if key_hex.is_empty() {
        key_hex = receipts[0]
            .get("signer_key")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
    }

    let mut prev_hash = String::new();
    for (index, receipt) in receipts.iter().enumerate() {
        let Some(seq) = receipt
            .get("action_record")
            .and_then(|record| record.get("chain_seq"))
            .and_then(|value| value.as_u64())
        else {
            return broken(
                index as u64,
                format!("seq {index}: missing or invalid chain_seq"),
            );
        };
        if let Err(err) = verify_receipt_with_options(receipt, &key_hex, allow_unpinned) {
            return broken(seq, format!("seq {seq}: signature: {err}"));
        }
        if seq != index as u64 {
            return broken(seq, format!("seq gap: expected {index}, got {seq}"));
        }
        let chain_prev_hash = receipt
            .get("action_record")
            .and_then(|record| record.get("chain_prev_hash"))
            .and_then(|value| value.as_str());
        if index == 0 {
            if let Some(result) = validate_action_genesis(receipt, chain_prev_hash, seq) {
                return result;
            }
        } else if chain_prev_hash != Some(prev_hash.as_str()) {
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

pub fn compute_session_open_genesis(open: &serde_json::Value) -> String {
    let mut h = Sha256::new();
    fn frame(h: &mut Sha256, data: &[u8]) {
        h.update((data.len() as u64).to_be_bytes());
        h.update(data);
    }
    fn text_field<'a>(open: &'a serde_json::Value, name: &str) -> &'a [u8] {
        open.get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .as_bytes()
    }

    frame(&mut h, SESSION_OPEN_GENESIS_LABEL.as_bytes());
    frame(&mut h, text_field(open, "run_nonce"));
    frame(&mut h, text_field(open, "open_nonce"));
    frame(&mut h, text_field(open, "recorder_session"));
    frame(&mut h, text_field(open, "policy_hash"));
    frame(&mut h, text_field(open, "signer_key_epoch"));
    let hb_secs = open
        .get("heartbeat_seconds")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
        .max(0) as u64;
    frame(&mut h, &hb_secs.to_be_bytes());
    frame(&mut h, text_field(open, "genesis_anchor_head"));
    frame(&mut h, text_field(open, "genesis_anchor_log"));
    frame(&mut h, text_field(open, "posture_capsule_sha256"));
    frame(&mut h, text_field(open, "containment_nonce"));
    frame(&mut h, text_field(open, "contained_uid"));

    format!("{GENESIS_SESSION_OPEN_PREFIX}{}", hex::encode(h.finalize()))
}

fn validate_action_genesis(
    receipt: &Receipt,
    chain_prev_hash: Option<&str>,
    seq: u64,
) -> Option<ChainResult> {
    let open = session_open(receipt);
    let Some(chain_prev_hash) = chain_prev_hash else {
        return Some(broken(seq, format!("seq {seq}: chain_prev_hash mismatch")));
    };
    if chain_prev_hash.starts_with(GENESIS_SESSION_OPEN_PREFIX) {
        let Some(open) = open else {
            return Some(broken(
                seq,
                format!("seq {seq}: g1 chain_prev_hash requires session_control.open"),
            ));
        };
        if seq != 0 {
            return Some(broken(
                seq,
                format!("seq {seq}: bound session_open genesis must be chain_seq 0"),
            ));
        }
        let computed = compute_session_open_genesis(open);
        if chain_prev_hash != computed {
            return Some(broken(
                seq,
                format!("seq {seq}: session_open genesis hash mismatch"),
            ));
        }
        if open
            .get("genesis_hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            != computed
        {
            return Some(broken(
                seq,
                format!("seq {seq}: session_open genesis_hash mismatch"),
            ));
        }
        if open
            .get("chain_open_seq")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            != seq
        {
            return Some(broken(
                seq,
                format!("seq {seq}: session_open chain_open_seq does not match receipt chain_seq"),
            ));
        }
        if !open
            .get("prior_chain_head")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .is_empty()
            || open
                .get("prior_chain_seq")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                != 0
        {
            return Some(broken(
                seq,
                format!("seq {seq}: bound genesis session_open must not carry prior chain tail"),
            ));
        }
        return None;
    }
    if chain_prev_hash != GENESIS_HASH {
        return Some(broken(
            seq,
            format!(
                "seq {seq}: genesis receipt chain_prev_hash must be genesis or a bound session_open g1 hash"
            ),
        ));
    }
    if open.is_some() {
        return Some(broken(
            seq,
            format!("seq {seq}: session_open on legacy genesis must use bound g1 chain_prev_hash"),
        ));
    }
    None
}

fn session_open(receipt: &Receipt) -> Option<&serde_json::Value> {
    let ctrl = receipt.get("action_record")?.get("session_control")?;
    if ctrl.get("kind").and_then(serde_json::Value::as_str) != Some("session_open") {
        return None;
    }
    ctrl.get("open").filter(|open| open.is_object())
}

fn verify_evidence_chain(
    receipts: &[Receipt],
    expected_key_hex: &str,
    allow_unpinned: bool,
) -> ChainResult {
    let key_hex = expected_key_hex.to_ascii_lowercase();
    if key_hex.is_empty() && !allow_unpinned {
        return broken(0, UNPINNED_RECEIPT_BANNER.to_string());
    }
    let signer_id = signer_key_id(&receipts[0]);
    let mut prev_hash = GENESIS_HASH.to_string();
    for (index, receipt) in receipts.iter().enumerate() {
        let seq = receipt
            .get("chain_seq")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(index as u64);
        if receipt
            .get("record_type")
            .and_then(serde_json::Value::as_str)
            != Some(EVIDENCE_RECORD_TYPE)
        {
            return broken(seq, format!("seq {seq}: mixed receipt record_type"));
        }
        let verify_result = if key_hex.is_empty() {
            normalize_evidence_receipt(receipt)
        } else {
            verify_receipt(receipt, &key_hex)
        };
        if let Err(err) = verify_result {
            return broken(seq, format!("seq {seq}: signature: {err}"));
        }
        if signer_key_id(receipt) != signer_id {
            return broken(
                seq,
                format!("seq {seq}: signer_key_id breaks chain signer {signer_id}"),
            );
        }
        if seq != index as u64 {
            return broken(seq, format!("seq gap: expected {index}, got {seq}"));
        }
        let chain_prev_hash = receipt
            .get("chain_prev_hash")
            .and_then(serde_json::Value::as_str);
        if chain_prev_hash != Some(prev_hash.as_str()) {
            return broken(seq, format!("seq {seq}: chain_prev_hash mismatch"));
        }
        prev_hash = receipt_hash(receipt);
    }

    ChainResult {
        valid: true,
        receipt_count: receipts.len(),
        final_seq: receipts
            .last()
            .and_then(|receipt| receipt.get("chain_seq"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        root_hash: prev_hash,
        error: None,
        broken_at_seq: None,
    }
}

fn signer_key_id(receipt: &Receipt) -> String {
    receipt
        .get("signature")
        .and_then(|value| value.get("signer_key_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string()
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
