mod common;

use ed25519_dalek::{Signer, SigningKey};
use pipelock_verifier_rs::canonical::canonicalize_jcs_value;
use pipelock_verifier_rs::chain::{receipt_hash, verify_chain, verify_chain_with_options};
use pipelock_verifier_rs::recorder::extract_receipts;
use serde_json::{json, Value};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

const V2_GOLDEN_PUBLIC_KEY: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const V2_PRIVATE_SEED_HEX: &str = concat!(
    "9d61b19d", "effd5a60", "ba844af4", "92ec2cc4", "4449c569", "7b326919", "703bac03", "1cae7f60"
);

#[test]
fn valid_go_generated_chain_verifies() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/valid-chain.jsonl")).unwrap();
    let result = verify_chain(&receipts, "");
    assert!(!result.valid);
    assert!(result.error.unwrap_or_default().contains("UNPINNED"));
}

#[test]
fn valid_go_generated_chain_allows_explicit_unpinned_structural_verification() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/valid-chain.jsonl")).unwrap();
    let result = verify_chain_with_options(&receipts, "", true);
    assert!(result.valid, "{:?}", result.error);
    assert_eq!(result.receipt_count, 5);
    assert_eq!(result.final_seq, 4);
    assert_eq!(
        result.root_hash,
        "be904bd5ca82adc26c2969872c23925f22ff24e33faf44a1185b9ffc0e2c2b5a"
    );
}

#[test]
fn broken_chain_prev_hash_is_rejected() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/broken-chain.jsonl")).unwrap();
    let result = verify_chain_with_options(&receipts, "", true);
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(3));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("chain_prev_hash mismatch"));
}

#[test]
fn missing_chain_seq_is_rejected_before_signature_check() {
    let root = common::repo_root();
    let mut receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/valid-chain.jsonl")).unwrap();
    if let Some(Value::Object(action_record)) = receipts[0].get_mut("action_record") {
        action_record.remove("chain_seq");
    }
    let result = verify_chain_with_options(&receipts, "", true);
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(0));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("missing or invalid chain_seq"));
}

#[test]
fn evidence_v2_multi_receipt_chain_verifies() {
    let receipts = build_evidence_chain(2);
    let result = verify_chain(&receipts, V2_GOLDEN_PUBLIC_KEY);
    assert!(result.valid, "{:?}", result.error);
    assert_eq!(result.receipt_count, 2);
    assert_eq!(result.final_seq, 1);
}

#[test]
fn evidence_v2_tampered_chain_fails_closed() {
    let mut receipts = build_evidence_chain(2);
    receipts[1]["chain_prev_hash"] = json!("sha256:0");
    let result = verify_chain(&receipts, V2_GOLDEN_PUBLIC_KEY);
    assert!(!result.valid);
    let error = result.error.unwrap_or_default();
    assert!(error.contains("signature") || error.contains("chain_prev_hash"));
}

#[test]
fn evidence_v2_truncated_middle_receipt_fails_closed() {
    let mut receipts = build_evidence_chain(3);
    receipts.remove(1);
    let result = verify_chain(&receipts, V2_GOLDEN_PUBLIC_KEY);
    assert!(!result.valid);
    let error = result.error.unwrap_or_default();
    assert!(error.contains("signature") || error.contains("seq gap"));
}

#[test]
fn recorder_extraction_rejects_duplicate_keys_inside_receipt_detail() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "pipelock-rs-verifier-{}-{suffix}.jsonl",
        std::process::id()
    ));
    let line = r#"{"v":1,"seq":0,"ts":"2026-05-10T00:00:00Z","session_id":"s","type":"action_receipt","transport":"https","summary":"","detail":{"version":1,"action_record":{"version":1,"action_id":"x","action_type":"write","timestamp":"2026-04-15T12:00:00Z","target":"https://e.example","verdict":"allow","verdict":"block","transport":"https","chain_prev_hash":"genesis","chain_seq":0},"signature":"ed25519:00","signer_key":"00"},"prev_hash":"genesis","hash":"h"}"#;
    fs::write(&path, format!("{line}\n")).expect("write JSONL");
    let err = extract_receipts(&path).expect_err("duplicate key should reject");
    let _ = fs::remove_file(&path);
    assert!(err.to_string().contains("duplicate object key"));
}

fn build_evidence_chain(count: usize) -> Vec<Value> {
    let root = common::repo_root();
    let base: Value =
        serde_json::from_str(
            &fs::read_to_string(root.join(
                "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json",
            ))
            .expect("read v2 fixture"),
        )
        .expect("parse v2 fixture");
    let mut receipts = Vec::new();
    let mut prev_hash = "genesis".to_string();
    for i in 0..count {
        let mut receipt = base.clone();
        receipt["event_id"] = json!(format!("01F8MECHZX3TBDSZ7XRADM79V{i}"));
        receipt["chain_seq"] = json!(i);
        receipt["chain_prev_hash"] = json!(prev_hash);
        sign_evidence_receipt(&mut receipt);
        prev_hash = receipt_hash(&receipt);
        receipts.push(receipt);
    }
    receipts
}

fn sign_evidence_receipt(receipt: &mut Value) {
    let signer_key_id = receipt["signature"]["signer_key_id"]
        .as_str()
        .unwrap_or("receipt-signing-test")
        .to_string();
    let mut clone = receipt.clone();
    clone["signature"] = json!({
        "signer_key_id": "",
        "key_purpose": "",
        "algorithm": "",
        "signature": ""
    });
    let seed: [u8; 32] = hex::decode(V2_PRIVATE_SEED_HEX)
        .expect("decode seed")
        .try_into()
        .expect("seed length");
    let key = SigningKey::from_bytes(&seed);
    let signature = key.sign(&canonicalize_jcs_value(&clone).expect("canonicalize receipt"));
    receipt["signature"] = json!({
        "signer_key_id": signer_key_id,
        "key_purpose": "receipt-signing",
        "algorithm": "ed25519",
        "signature": format!("ed25519:{}", hex::encode(signature.to_bytes()))
    });
}
